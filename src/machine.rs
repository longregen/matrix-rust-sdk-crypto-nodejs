//! The crypto specific Olm objects.

use std::{
    collections::{BTreeMap, HashMap},
    mem::ManuallyDrop,
    ops::Deref,
    sync::Arc,
};

use matrix_sdk_common::ruma::{
    events::AnyMessageLikeEvent, serde::Raw, OneTimeKeyAlgorithm, OwnedTransactionId, UInt,
};
use matrix_sdk_crypto::{
    backups::MegolmV1BackupKey, olm::ExportedRoomKey, store::CrossSigningKeyExport,
    types::RoomKeyBackupInfo, DecryptionSettings, EncryptionSyncChanges, TrustRequirement,
    Verification as InnerVerification,
};
use napi::bindgen_prelude::{within_runtime_if_available, Either6};
use napi_derive::*;
use serde_json::value::RawValue;
use zeroize::Zeroize;

use crate::{
    backup::{BackupDecryptionKey, BackupKeys, RoomKeyCounts},
    device, encryption, identifiers, into_err, olm, requests, responses,
    responses::response_from_string,
    sync_events,
    types::{self, SignatureVerification},
    verification, vodozemac,
};

/// Result of `receiveSyncChanges`.
#[napi(object)]
pub struct ReceiveSyncChangesResult {
    /// JSON-encoded array of decrypted to-device events.
    pub events: String,
    /// Information about room keys that were part of the sync.
    pub room_key_infos: Vec<RoomKeyInfoResult>,
}

/// Information on a room key that was received or updated.
#[napi(object)]
pub struct RoomKeyInfoResult {
    /// The encryption algorithm (e.g. `m.megolm.v1.aes-sha2`).
    pub algorithm: String,
    /// The room ID this key is for.
    pub room_id: String,
    /// The Curve25519 key of the sender, base64-encoded.
    pub sender_key: String,
    /// The session ID.
    pub session_id: String,
}

/// Result of importing room keys.
#[napi(object)]
pub struct ImportRoomKeysResult {
    /// The number of room keys that were imported.
    pub imported_count: f64,
    /// The total number of room keys in the export.
    pub total_count: f64,
    /// JSON-encoded map of room_id -> sender_key -> [session_ids].
    pub keys: String,
}

/// Exported private cross-signing keys.
#[napi(object)]
pub struct CrossSigningKeyExportResult {
    /// The master key, if available.
    pub master_key: Option<String>,
    /// The self-signing key, if available.
    pub self_signing_key: Option<String>,
    /// The user-signing key, if available.
    pub user_signing_key: Option<String>,
}

/// The value used by the `OlmMachine` JS class.
///
/// It has 2 states: `Opened` and `Closed`. Why maintaining the state here?
/// Because NodeJS has no way to drop an object explicitly, and we want to be
/// able to “close” the `OlmMachine` to free all associated data. More over,
/// `napi-rs` doesn't allow a function to take the ownership of the type itself
/// (`fn close(self) { … }`). So we manage the state ourselves.
///
/// Using the `OlmMachine` when its state is `Closed` will panic.
enum OlmMachineInner {
    Opened(ManuallyDrop<matrix_sdk_crypto::OlmMachine>),
    Closed,
}

impl Drop for OlmMachineInner {
    fn drop(&mut self) {
        if let Self::Opened(machine) = self {
            // SAFETY: `self` won't be used anymore after this `take`, so it's safe to do it
            // here.
            let machine = unsafe { ManuallyDrop::take(machine) };
            within_runtime_if_available(move || drop(machine));
        }
    }
}

impl Deref for OlmMachineInner {
    type Target = matrix_sdk_crypto::OlmMachine;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Opened(machine) => machine,
            Self::Closed => panic!("The `OlmMachine` has been closed, cannot use it anymore"),
        }
    }
}

/// Represents the type of store an `OlmMachine` can use.
#[derive(Default)]
#[napi]
pub enum StoreType {
    /// Use `matrix-sdk-sqlite`.
    #[default]
    Sqlite,
}

/// State machine implementation of the Olm/Megolm encryption protocol
/// used for Matrix end to end encryption.
// #[napi(custom_finalize)]
#[napi]
pub struct OlmMachine {
    inner: OlmMachineInner,
}

#[napi]
impl OlmMachine {
    // JavaScript doesn't support asynchronous constructor. So let's
    // use a factory pattern, where the constructor cannot be used (it
    // returns an error), and a new method is provided to construct
    // the object. napi provides `#[napi(factory)]` to address those
    // needs automatically. Unfortunately, it doesn't support
    // asynchronous factory methods.
    //
    // So let's do this manually. The `initialize` async method _is_
    // the factory function. We also manually implement the
    // constructor to raise an error when called.

    /// Create a new `OlmMachine` asynchronously.
    ///
    /// The persistence of the encryption keys and all the inner
    /// objects are controlled by the `store_path` argument.
    ///
    /// # Arguments
    ///
    /// * `user_id`, the unique ID of the user that owns this machine.
    /// * `device_id`, the unique id of the device that owns this machine.
    /// * `store_path`, the path to a directory where the state of the machine
    ///   should be persisted; if not set, the created machine will keep the
    ///   encryption keys only in memory, and once the object is dropped, the
    ///   keys will be lost.
    /// * `store_passphrase`, the passphrase that should be used to encrypt the
    ///   data at rest in the store. **Warning**, if no passphrase is given, the
    ///   store and all its data will remain unencrypted. This argument is
    ///   ignored if `store_path` is not set.
    #[napi(strict)]
    pub async fn initialize(
        user_id: &identifiers::UserId,
        device_id: &identifiers::DeviceId,
        store_path: Option<String>,
        mut store_passphrase: Option<String>,
        store_type: Option<StoreType>,
    ) -> napi::Result<OlmMachine> {
        let user_id = user_id.clone().inner;
        let device_id = device_id.clone().inner;

        let user_id = user_id.as_ref();
        let device_id = device_id.as_ref();

        Ok(OlmMachine {
            inner: OlmMachineInner::Opened(ManuallyDrop::new(match store_path {
                Some(store_path) => {
                    let machine = match store_type.unwrap_or_default() {
                        StoreType::Sqlite => {
                            matrix_sdk_crypto::OlmMachine::with_store(
                                user_id,
                                device_id,
                                matrix_sdk_sqlite::SqliteCryptoStore::open(
                                    store_path,
                                    store_passphrase.as_deref(),
                                )
                                .await
                                .map(Arc::new)
                                .map_err(into_err)?,
                                None,
                            )
                            .await
                        }
                    };

                    store_passphrase.zeroize();

                    machine.map_err(into_err)?
                }

                None => matrix_sdk_crypto::OlmMachine::new(user_id, device_id).await,
            })),
        })
    }

    /// It's not possible to construct an `OlmMachine` with its
    /// constructor because building an `OlmMachine` is
    /// asynchronous. Please use the `finalize` method.
    #[napi(constructor)]
    pub fn new() -> napi::Result<Self> {
        Err(napi::Error::from_reason(
            "To build an `OlmMachine`, please use the `initialize` method",
        ))
    }

    /// The unique user ID that owns this `OlmMachine` instance.
    #[napi(getter)]
    pub fn user_id(&self) -> identifiers::UserId {
        identifiers::UserId::from(self.inner.user_id().to_owned())
    }

    /// The unique device ID that identifies this `OlmMachine`.
    #[napi(getter)]
    pub fn device_id(&self) -> identifiers::DeviceId {
        identifiers::DeviceId::from(self.inner.device_id().to_owned())
    }

    /// Get the public parts of our Olm identity keys.
    #[napi(getter)]
    pub fn identity_keys(&self) -> vodozemac::IdentityKeys {
        self.inner.identity_keys().into()
    }

    /// Handle a to-device and one-time key counts from a sync response.
    ///
    /// This will decrypt and handle to-device events returning the
    /// decrypted versions of them, as a JSON-encoded string.
    ///
    /// To decrypt an event from the room timeline, please use
    /// `decrypt_room_event`.
    ///
    /// # Arguments
    ///
    /// * `to_device_events`, the to-device events of the current sync response.
    /// * `changed_devices`, the list of devices that changed in this sync
    ///   response.
    /// * `one_time_keys_count`, the current one-time keys counts that the sync
    ///   response returned.
    #[napi(strict)]
    pub async fn receive_sync_changes(
        &self,
        to_device_events: String,
        changed_devices: &sync_events::DeviceLists,
        one_time_key_counts: HashMap<String, u32>,
        unused_fallback_keys: Vec<String>,
    ) -> napi::Result<ReceiveSyncChangesResult> {
        let to_device_events_decoded =
            serde_json::from_str(to_device_events.as_ref()).map_err(into_err)?;
        let changed_devices = changed_devices.inner.clone();
        let one_time_key_counts = one_time_key_counts
            .iter()
            .map(|(key, value)| (OneTimeKeyAlgorithm::from(key.as_str()), UInt::from(*value)))
            .collect::<BTreeMap<_, _>>();
        let unused_fallback_keys = Some(
            unused_fallback_keys
                .into_iter()
                .map(|key| OneTimeKeyAlgorithm::from(key.as_str()))
                .collect::<Vec<_>>(),
        );

        let (events_raw, room_key_infos_raw) = self
            .inner
            .receive_sync_changes(EncryptionSyncChanges {
                to_device_events: to_device_events_decoded,
                changed_devices: &changed_devices,
                one_time_keys_counts: &one_time_key_counts,
                unused_fallback_keys: unused_fallback_keys.as_deref(),
                next_batch_token: None,
            })
            .await
            .map_err(into_err)?;

        let events = serde_json::to_string(&events_raw).map_err(into_err)?;
        let room_key_infos = room_key_infos_raw
            .into_iter()
            .map(|rki| RoomKeyInfoResult {
                algorithm: rki.algorithm.to_string(),
                room_id: rki.room_id.to_string(),
                sender_key: rki.sender_key.to_base64(),
                session_id: rki.session_id,
            })
            .collect();

        Ok(ReceiveSyncChangesResult { events, room_key_infos })
    }

    /// Get the outgoing requests that need to be sent out.
    ///
    /// This returns a list of `KeysUploadRequest`, or
    /// `KeysQueryRequest`, or `KeysClaimRequest`, or
    /// `ToDeviceRequest`, or `SignatureUploadRequest`, or
    /// `RoomMessageRequest`. Those requests
    /// need to be sent out to the server and the responses need to be
    /// passed back to the state machine using `mark_request_as_sent`.
    #[napi]
    pub async fn outgoing_requests(
        &self,
    ) -> napi::Result<
        Vec<
            // We could be tempted to use `requests::OutgoingRequests` as its
            // a type alias for this giant `Either6`. But `napi` won't unfold
            // it properly into a valid TypeScript definition, so…  let's
            // copy-paste :-(.
            Either6<
                requests::KeysUploadRequest,
                requests::KeysQueryRequest,
                requests::KeysClaimRequest,
                requests::ToDeviceRequest,
                requests::SignatureUploadRequest,
                requests::RoomMessageRequest,
            >,
        >,
    > {
        self.inner
            .outgoing_requests()
            .await
            .map_err(into_err)?
            .into_iter()
            .map(requests::OutgoingRequest)
            .map(TryFrom::try_from)
            .collect()
    }

    /// Mark the request with the given request ID as sent.
    ///
    /// # Arguments
    ///
    /// * `request_id`, the unique ID of the request that was sent out. This is
    ///   needed to couple the response with the now sent out request.
    /// * `request_type`, the request type associated to the request ID.
    /// * `response`, the response that was received from the server after the
    ///   outgoing request was sent out.
    #[napi(strict)]
    pub async fn mark_request_as_sent(
        &self,
        request_id: String,
        request_type: requests::RequestType,
        response: String,
    ) -> napi::Result<bool> {
        let transaction_id = OwnedTransactionId::from(request_id);
        let response = response_from_string(response.as_str()).map_err(into_err)?;
        let incoming_response = responses::OwnedResponse::try_from((request_type, response))?;

        self.inner
            .mark_request_as_sent(&transaction_id, &incoming_response)
            .await
            .map(|_| true)
            .map_err(into_err)
    }

    /// Get the a key claiming request for the user/device pairs that
    /// we are missing Olm sessions for.
    ///
    /// Returns `null` if no key claiming request needs to be sent
    /// out.
    ///
    /// Sessions need to be established between devices so group
    /// sessions for a room can be shared with them.
    ///
    /// This should be called every time a group session needs to be
    /// shared as well as between sync calls. After a sync some
    /// devices may request room keys without us having a valid Olm
    /// session with them, making it impossible to server the room key
    /// request, thus it’s necessary to check for missing sessions
    /// between sync as well.
    ///
    /// Note: Care should be taken that only one such request at a
    /// time is in flight, e.g. using a lock.
    ///
    /// The response of a successful key claiming requests needs to be
    /// passed to the `OlmMachine` with the `mark_request_as_sent`.
    ///
    /// # Arguments
    ///
    /// * `users`, the list of users that we should check if we lack a session
    ///   with one of their devices. This can be an empty array or `null` when
    ///   calling this method between sync requests.
    #[napi(strict)]
    pub async fn get_missing_sessions(
        &self,
        users: Option<Vec<&identifiers::UserId>>,
    ) -> napi::Result<Option<requests::KeysClaimRequest>> {
        let users = users
            .unwrap_or_default()
            .into_iter()
            .map(|user| user.inner.clone())
            .collect::<Vec<_>>();

        match self
            .inner
            .get_missing_sessions(users.iter().map(AsRef::as_ref))
            .await
            .map_err(into_err)?
        {
            Some((transaction_id, keys_claim_request)) => Ok(Some(
                requests::KeysClaimRequest::try_from((
                    transaction_id.to_string(),
                    &keys_claim_request,
                ))
                .map_err(into_err)?,
            )),

            None => Ok(None),
        }
    }

    /// Update the tracked users.
    ///
    /// This will mark users that weren’t seen before for a key query
    /// and tracking.
    ///
    /// If the user is already known to the Olm machine it will not be
    /// considered for a key query.
    ///
    /// # Arguments
    ///
    /// * `users`, an array over user IDs that should be marked for tracking.
    #[napi(strict)]
    pub async fn update_tracked_users(&self, users: Vec<&identifiers::UserId>) -> napi::Result<()> {
        let users = users.into_iter().map(|user| user.inner.clone()).collect::<Vec<_>>();

        self.inner.update_tracked_users(users.iter().map(AsRef::as_ref)).await.map_err(into_err)?;

        Ok(())
    }

    /// Get to-device requests to share a room key with users in a room.
    ///
    /// # Arguments
    ///
    /// * `room_id`, the room ID of the room where the room key will be used.
    /// * `users`, the list of users that should receive the room key.
    /// * `encryption_settings`, the encryption settings.
    #[napi(strict)]
    pub async fn share_room_key(
        &self,
        room_id: &identifiers::RoomId,
        users: Vec<&identifiers::UserId>,
        encryption_settings: &encryption::EncryptionSettings,
    ) -> napi::Result<Vec<requests::ToDeviceRequest>> {
        let room_id = room_id.inner.clone();
        let users = users.into_iter().map(|user| user.inner.clone()).collect::<Vec<_>>();
        let encryption_settings =
            matrix_sdk_crypto::olm::EncryptionSettings::from(encryption_settings);

        self.inner
            .share_room_key(&room_id, users.iter().map(AsRef::as_ref), encryption_settings)
            .await
            .map_err(into_err)?
            .into_iter()
            .map(|td| requests::ToDeviceRequest::try_from(td.deref()))
            .collect()
    }

    /// Encrypt a JSON-encoded content for the given room.
    ///
    /// # Arguments
    ///
    /// * `room_id`, the ID of the room for which the message should be
    ///   encrypted.
    /// * `event_type`, the plaintext type of the event.
    /// * `content`, the JSON-encoded content of the message that should be
    ///   encrypted.
    #[napi(strict)]
    pub async fn encrypt_room_event(
        &self,
        room_id: &identifiers::RoomId,
        event_type: String,
        content: String,
    ) -> napi::Result<String> {
        let room_id = room_id.inner.clone();
        let content = serde_json::from_str(content.as_str()).map_err(into_err)?;
        serde_json::to_string(
            &self
                .inner
                .encrypt_room_event_raw(&room_id, event_type.as_ref(), &content)
                .await
                .map_err(into_err)?,
        )
        .map_err(into_err)
    }

    /// Decrypt an event from a room timeline.
    ///
    /// # Arguments
    ///
    /// * `event`, the event that should be decrypted.
    /// * `room_id`, the ID of the room where the event was sent to.
    #[napi(strict)]
    pub async fn decrypt_room_event(
        &self,
        event: String,
        room_id: &identifiers::RoomId,
    ) -> napi::Result<responses::DecryptedRoomEvent> {
        let event = Raw::from_json(RawValue::from_string(event).map_err(into_err)?);
        let room_id = room_id.inner.clone();

        let decryption_settings =
            DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted };

        let room_event = self
            .inner
            .decrypt_room_event(&event, &room_id, &decryption_settings)
            .await
            .map_err(into_err)?;

        Ok(room_event.into())
    }

    /// Get the status of the private cross signing keys.
    ///
    /// This can be used to check which private cross signing keys we
    /// have stored locally.
    #[napi]
    pub async fn cross_signing_status(&self) -> olm::CrossSigningStatus {
        self.inner.cross_signing_status().await.into()
    }

    /// Create a new cross signing identity and get the upload request
    /// to push the new public keys to the server.
    ///
    /// Warning: This will delete any existing cross signing keys that
    /// might exist on the server and thus will reset the trust
    /// between all the devices.
    ///
    /// Uploading these keys will require user interactive auth.
    ///
    /// # Arguments
    ///
    /// * `reset`, whether the method should create a new identity or use the
    ///   existing one during the request. If set to true, the request will
    ///   attempt to upload a new identity. If set to false, the request will
    ///   attempt to upload the existing identity. Since the uploading process
    ///   requires user interactive authentication, which involves sending out
    ///   the same request multiple times, setting this argument to false
    ///   enables you to reuse the same request.
    #[napi]
    pub async fn bootstrap_cross_signing(&self, reset: bool) -> napi::Result<()> {
        self.inner.bootstrap_cross_signing(reset).await.map_err(into_err)?;
        Ok(())
    }

    /// Sign the given message using our device key and if available
    /// cross-signing master key.
    #[napi(strict)]
    pub async fn sign(&self, message: String) -> napi::Result<types::Signatures> {
        Ok(self.inner.sign(&message).await.map_err(into_err)?.into())
    }

    /// Store the backup decryption key in the crypto store.
    ///
    /// This is useful if the client wants to support gossiping of the backup
    /// key.
    #[napi(strict)]
    pub async fn save_backup_decryption_key(
        &self,
        decryption_key: &BackupDecryptionKey,
        version: String,
    ) -> napi::Result<()> {
        self.inner
            .backup_machine()
            .save_decryption_key(Some(decryption_key.inner.clone()), Some(version))
            .await
            .map_err(into_err)?;
        Ok(())
    }

    /// Get the backup keys we have saved in our store.
    #[napi]
    pub async fn get_backup_keys(&self) -> napi::Result<BackupKeys> {
        let inner = self.inner.backup_machine().get_backup_keys().await.map_err(into_err)?;
        Ok(BackupKeys {
            decryption_key_base64: inner.decryption_key.map(|k| k.to_base64()),
            backup_version: inner.backup_version,
        })
    }

    /// Check if the given backup has been verified by us or by another of our
    /// devices that we trust.
    ///
    /// The `backup_info` should be a stringified JSON object with the following
    /// format:
    ///
    /// ```json
    /// {
    ///     "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
    ///     "auth_data": {
    ///         "public_key":"XjhWTCjW7l59pbfx9tlCBQolfnIQWARoKOzjTOPSlWM",
    ///         "signatures": {}
    ///     }
    /// }
    /// ```
    #[napi(strict)]
    pub async fn verify_backup(&self, backup_info: String) -> napi::Result<SignatureVerification> {
        let backup_info: RoomKeyBackupInfo =
            serde_json::from_str(backup_info.as_str()).map_err(into_err)?;

        Ok(SignatureVerification {
            inner: self
                .inner
                .backup_machine()
                .verify_backup(backup_info, false)
                .await
                .map_err(into_err)?,
        })
    }

    /// Activate the given backup key to be used with the given backup version.
    ///
    /// **Warning**: The caller needs to make sure that the given `BackupKey` is
    /// trusted, otherwise we might be encrypting room keys that a malicious
    /// party could decrypt.
    ///
    /// The [`OlmMachine::verify_backup`] method can be used to do so.
    #[napi(strict)]
    pub async fn enable_backup_v1(
        &self,
        public_key_base_64: String,
        version: String,
    ) -> napi::Result<()> {
        let backup_key = MegolmV1BackupKey::from_base64(&public_key_base_64).map_err(into_err)?;
        backup_key.set_version(version);

        self.inner.backup_machine().enable_backup_v1(backup_key).await.map_err(into_err)?;
        Ok(())
    }

    /// Are we able to encrypt room keys.
    ///
    /// This returns true if we have an active `BackupKey` and backup version
    /// registered with the state machine.
    #[napi]
    pub async fn is_backup_enabled(&self) -> bool {
        self.inner.backup_machine().enabled().await
    }

    /// Disable and reset our backup state.
    ///
    /// This will remove any pending backup request, remove the backup key and
    /// reset the backup state of each room key we have.
    #[napi]
    pub async fn disable_backup(&self) -> napi::Result<()> {
        self.inner.backup_machine().disable_backup().await.map_err(into_err)?;
        Ok(())
    }

    /// Encrypt a batch of room keys and return a request that needs to be sent
    /// out to backup the room keys.
    #[napi]
    pub async fn backup_room_keys(&self) -> napi::Result<Option<requests::KeysBackupRequest>> {
        match self.inner.backup_machine().backup().await.map_err(into_err)? {
            Some((transaction_id, keys_backup_request)) => Ok(Some(
                requests::KeysBackupRequest::try_from((
                    transaction_id.to_string(),
                    &keys_backup_request,
                ))
                .map_err(into_err)?,
            )),

            None => Ok(None),
        }
    }

    /// Export room keys in unencrypted format for a given session_id.
    /// This currently exports a json blob.
    #[napi]
    pub async fn export_room_keys_for_session(
        &self,
        room_id: String,
        session_id: String,
    ) -> napi::Result<String> {
        serde_json::to_string(
            &self
                .inner
                .store()
                .export_room_keys(|session| {
                    session.session_id() == session_id && session.room_id() == &room_id
                })
                .await
                .map_err(into_err)?,
        )
        .map_err(into_err)
    }

    /// Get the number of backed up room keys and the total number of room keys.
    #[napi]
    pub async fn room_key_counts(&self) -> napi::Result<RoomKeyCounts> {
        Ok(self.inner.backup_machine().room_key_counts().await.map_err(into_err)?.into())
    }

    /// Import previously exported room keys into the crypto store.
    ///
    /// # Arguments
    ///
    /// * `exported_keys_json`, a JSON-encoded array of exported room keys.
    #[napi(strict)]
    pub async fn import_exported_room_keys(
        &self,
        exported_keys_json: String,
    ) -> napi::Result<ImportRoomKeysResult> {
        let keys: Vec<ExportedRoomKey> =
            serde_json::from_str(&exported_keys_json).map_err(into_err)?;
        let result =
            self.inner.store().import_exported_room_keys(keys, |_, _| {}).await.map_err(into_err)?;

        Ok(ImportRoomKeysResult {
            imported_count: result.imported_count.try_into().unwrap_or(u32::MAX).into(),
            total_count: result.total_count.try_into().unwrap_or(u32::MAX).into(),
            keys: serde_json::to_string(&result.keys).map_err(into_err)?,
        })
    }

    /// Export all room keys as a JSON-encoded string.
    #[napi]
    pub async fn export_room_keys(&self) -> napi::Result<String> {
        serde_json::to_string(
            &self.inner.store().export_room_keys(|_| true).await.map_err(into_err)?,
        )
        .map_err(into_err)
    }

    /// Mark all tracked users as dirty, triggering key re-queries
    /// on the next sync.
    #[napi]
    pub async fn mark_all_tracked_users_as_dirty(&self) -> napi::Result<()> {
        self.inner.mark_all_tracked_users_as_dirty().await.map_err(into_err)
    }

    /// Check if the room key for the given encrypted event is
    /// available in the store.
    ///
    /// # Arguments
    ///
    /// * `event`, the JSON-encoded encrypted event.
    /// * `room_id`, the room ID where the event was sent.
    #[napi(strict)]
    pub async fn is_room_key_available(
        &self,
        event: String,
        room_id: &identifiers::RoomId,
    ) -> napi::Result<bool> {
        let event = Raw::from_json(RawValue::from_string(event).map_err(into_err)?);
        let room_id = room_id.inner.clone();
        self.inner.is_room_key_available(&event, &room_id).await.map_err(into_err)
    }

    /// Request a room key from other devices for the given encrypted event.
    ///
    /// Returns the outgoing requests that need to be sent (may include
    /// a cancellation for a previous request).
    ///
    /// # Arguments
    ///
    /// * `event`, the JSON-encoded encrypted event.
    /// * `room_id`, the room ID where the event was sent.
    #[napi(strict)]
    pub async fn request_room_key(
        &self,
        event: String,
        room_id: &identifiers::RoomId,
    ) -> napi::Result<
        Vec<
            Either6<
                requests::KeysUploadRequest,
                requests::KeysQueryRequest,
                requests::KeysClaimRequest,
                requests::ToDeviceRequest,
                requests::SignatureUploadRequest,
                requests::RoomMessageRequest,
            >,
        >,
    > {
        let event = Raw::from_json(RawValue::from_string(event).map_err(into_err)?);
        let room_id = room_id.inner.clone();
        let (cancellation, key_request) =
            self.inner.request_room_key(&event, &room_id).await.map_err(into_err)?;

        let mut results = Vec::new();
        if let Some(cancel) = cancellation {
            results.push(requests::OutgoingRequest(cancel).try_into()?);
        }
        results.push(requests::OutgoingRequest(key_request).try_into()?);
        Ok(results)
    }

    /// Discard the currently active room key for the given room.
    ///
    /// Returns `true` if a room key was discarded, `false` if there
    /// was no active room key.
    #[napi(strict)]
    pub async fn discard_room_key(
        &self,
        room_id: &identifiers::RoomId,
    ) -> napi::Result<bool> {
        let room_id = room_id.inner.clone();
        self.inner.discard_room_key(&room_id).await.map_err(into_err)
    }

    /// Get a SAS verification object for the given user and flow ID.
    ///
    /// Returns `null` if no SAS verification exists for the given
    /// identifiers, or if the verification is QR-based.
    #[napi(strict)]
    pub fn get_sas_verification(
        &self,
        user_id: &identifiers::UserId,
        flow_id: String,
    ) -> Option<verification::Sas> {
        match self.inner.get_verification(user_id.inner.as_ref(), &flow_id) {
            Some(InnerVerification::SasV1(sas)) => {
                Some(verification::Sas { inner: sas })
            }
            _ => None,
        }
    }

    /// Get a verification request for the given user and flow ID.
    #[napi(strict)]
    pub fn get_verification_request(
        &self,
        user_id: &identifiers::UserId,
        flow_id: String,
    ) -> Option<verification::VerificationRequest> {
        self.inner
            .get_verification_request(user_id.inner.as_ref(), &flow_id)
            .map(|inner| verification::VerificationRequest { inner })
    }

    /// Get all verification requests for the given user.
    #[napi(strict)]
    pub fn get_verification_requests(
        &self,
        user_id: &identifiers::UserId,
    ) -> Vec<verification::VerificationRequest> {
        self.inner
            .get_verification_requests(user_id.inner.as_ref())
            .into_iter()
            .map(|inner| verification::VerificationRequest { inner })
            .collect()
    }

    /// Receive and process a verification event.
    ///
    /// # Arguments
    ///
    /// * `event`, the JSON-encoded verification event.
    #[napi(strict)]
    pub async fn receive_verification_event(&self, event: String) -> napi::Result<()> {
        let event: AnyMessageLikeEvent =
            serde_json::from_str(&event).map_err(into_err)?;
        self.inner.receive_verification_event(&event).await.map_err(into_err)
    }

    /// Get a device by its user ID and device ID.
    #[napi(strict)]
    pub async fn get_device(
        &self,
        user_id: &identifiers::UserId,
        device_id: &identifiers::DeviceId,
    ) -> napi::Result<Option<device::Device>> {
        let user_id = user_id.inner.clone();
        let device_id = device_id.inner.clone();
        let device =
            self.inner.get_device(&user_id, &device_id, None).await.map_err(into_err)?;
        Ok(device.map(|d| device::Device { inner: d }))
    }

    /// Get all devices for a user.
    #[napi(strict)]
    pub async fn get_user_devices(
        &self,
        user_id: &identifiers::UserId,
    ) -> napi::Result<Vec<device::Device>> {
        let user_id = user_id.inner.clone();
        let devices = self.inner.get_user_devices(&user_id, None).await.map_err(into_err)?;
        Ok(devices.devices().map(|d| device::Device { inner: d }).collect())
    }

    /// Get the user identity for the given user ID.
    #[napi(strict)]
    pub async fn get_identity(
        &self,
        user_id: &identifiers::UserId,
    ) -> napi::Result<Option<device::UserIdentity>> {
        let user_id = user_id.inner.clone();
        let identity = self.inner.get_identity(&user_id, None).await.map_err(into_err)?;
        Ok(identity.map(|i| device::UserIdentity { inner: i }))
    }

    /// Export the private cross-signing keys.
    ///
    /// Returns `null` if no cross-signing keys are available.
    #[napi]
    pub async fn export_cross_signing_keys(
        &self,
    ) -> napi::Result<Option<CrossSigningKeyExportResult>> {
        match self.inner.export_cross_signing_keys().await.map_err(into_err)? {
            Some(export) => Ok(Some(CrossSigningKeyExportResult {
                master_key: export.master_key.clone(),
                self_signing_key: export.self_signing_key.clone(),
                user_signing_key: export.user_signing_key.clone(),
            })),
            None => Ok(None),
        }
    }

    /// Import private cross-signing keys.
    #[napi(strict)]
    pub async fn import_cross_signing_keys(
        &self,
        master_key: Option<String>,
        self_signing_key: Option<String>,
        user_signing_key: Option<String>,
    ) -> napi::Result<olm::CrossSigningStatus> {
        let export = CrossSigningKeyExport { master_key, self_signing_key, user_signing_key };
        Ok(self.inner.import_cross_signing_keys(export).await.map_err(into_err)?.into())
    }

    /// Generate a key query request for the given users.
    ///
    /// This creates an out-of-band key query request that can be
    /// sent independently of sync.
    #[napi(strict)]
    pub fn query_keys_for_users(
        &self,
        users: Vec<&identifiers::UserId>,
    ) -> napi::Result<requests::KeysQueryRequest> {
        let users = users.into_iter().map(|user| user.inner.clone()).collect::<Vec<_>>();
        let (txn_id, request) =
            self.inner.query_keys_for_users(users.iter().map(AsRef::as_ref));
        requests::KeysQueryRequest::try_from((txn_id.to_string(), &request))
    }

    /// Get the display name of this device.
    #[napi]
    pub async fn display_name(&self) -> napi::Result<Option<String>> {
        self.inner.display_name().await.map_err(into_err)
    }

    /// Get the device creation timestamp in milliseconds since
    /// the Unix epoch.
    #[napi(getter)]
    pub fn device_creation_time(&self) -> f64 {
        let ts = self.inner.device_creation_time();
        u64::from(ts.0) as f64
    }

    /// Shut down the `OlmMachine`.
    ///
    /// The `OlmMachine` cannot be used after this method has been called,
    /// otherwise it will panic.
    ///
    /// All associated resources will be closed too, like the crypto storage
    /// connections.
    ///
    /// # Safety
    ///
    /// The caller is responsible to **not** use any objects that came from this
    /// `OlmMachine` after this `close` method has been called.
    #[napi(strict)]
    pub fn close(&mut self) {
        self.inner = OlmMachineInner::Closed;
    }
}
