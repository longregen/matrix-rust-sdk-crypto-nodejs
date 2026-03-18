//! Verification types for device and user verification.

use matrix_sdk_crypto::types::requests::OutgoingVerificationRequest;
use napi::bindgen_prelude::{Either, Either6};
use napi_derive::*;

use crate::{identifiers, into_err, requests};

/// Convert an OutgoingVerificationRequest to napi types.
pub(crate) fn outgoing_verification_to_napi(
    req: OutgoingVerificationRequest,
) -> napi::Result<Either<requests::ToDeviceRequest, requests::RoomMessageRequest>> {
    let request_id = req.request_id().to_string();
    match req {
        OutgoingVerificationRequest::ToDevice(td) => {
            Ok(Either::A(requests::ToDeviceRequest::try_from((request_id, &td))?))
        }
        OutgoingVerificationRequest::InRoom(rm) => {
            Ok(Either::B(requests::RoomMessageRequest::try_from((request_id, &rm))?))
        }
    }
}

/// An emoji representation for SAS verification.
#[napi(object)]
pub struct SasEmoji {
    /// The emoji symbol.
    pub symbol: String,
    /// A human-readable description of the emoji.
    pub description: String,
}

/// Type alias for the outgoing requests returned by various methods.
type OutgoingRequests = Either6<
    requests::KeysUploadRequest,
    requests::KeysQueryRequest,
    requests::KeysClaimRequest,
    requests::ToDeviceRequest,
    requests::SignatureUploadRequest,
    requests::RoomMessageRequest,
>;

/// Short Authentication String (SAS) verification.
#[napi]
pub struct Sas {
    pub(crate) inner: matrix_sdk_crypto::Sas,
}

#[napi]
impl Sas {
    /// Accept the SAS verification.
    ///
    /// Returns an outgoing request that needs to be sent, or `null`
    /// if the verification was already accepted.
    #[napi]
    pub fn accept(
        &self,
    ) -> napi::Result<Option<Either<requests::ToDeviceRequest, requests::RoomMessageRequest>>>
    {
        self.inner.accept().map(outgoing_verification_to_napi).transpose()
    }

    /// Get the emoji representation of the short authentication string.
    ///
    /// Returns `null` if the emojis are not yet available (SAS not
    /// in the right state).
    #[napi]
    pub fn emoji(&self) -> Option<Vec<SasEmoji>> {
        self.inner.emoji().map(|emojis| {
            emojis
                .iter()
                .map(|e| SasEmoji {
                    symbol: e.symbol.to_owned(),
                    description: e.description.to_owned(),
                })
                .collect()
        })
    }

    /// Get the emoji index (0–63) of the short authentication string.
    ///
    /// Returns `null` if not yet available.
    #[napi]
    pub fn emoji_index(&self) -> Option<Vec<u8>> {
        self.inner.emoji_index().map(|i| i.to_vec())
    }

    /// Get the decimal representation of the short authentication string.
    ///
    /// Returns three numbers, or `null` if not yet available.
    #[napi]
    pub fn decimals(&self) -> Option<Vec<u16>> {
        self.inner.decimals().map(|(a, b, c)| vec![a, b, c])
    }

    /// Confirm the SAS verification.
    ///
    /// Returns the outgoing requests that need to be sent out.
    /// These may include verification messages and an optional
    /// signature upload request.
    #[napi]
    pub async fn confirm(
        &self,
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
        let (reqs, sig) = self.inner.confirm().await.map_err(into_err)?;
        let mut results: Vec<OutgoingRequests> = Vec::new();

        for req in reqs {
            let request_id = req.request_id().to_string();
            match req {
                matrix_sdk_crypto::types::requests::OutgoingVerificationRequest::ToDevice(td) => {
                    results.push(Either6::D(
                        requests::ToDeviceRequest::try_from((request_id, &td))?,
                    ));
                }
                matrix_sdk_crypto::types::requests::OutgoingVerificationRequest::InRoom(rm) => {
                    results.push(Either6::F(
                        requests::RoomMessageRequest::try_from((request_id, &rm))?,
                    ));
                }
            }
        }

        if let Some(sig) = sig {
            results
                .push(Either6::E(requests::SignatureUploadRequest::try_from(&sig)?));
        }

        Ok(results)
    }

    /// Cancel the verification.
    #[napi]
    pub fn cancel(
        &self,
    ) -> napi::Result<Option<Either<requests::ToDeviceRequest, requests::RoomMessageRequest>>>
    {
        self.inner.cancel().map(outgoing_verification_to_napi).transpose()
    }

    /// Is the verification process done.
    #[napi(getter)]
    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    /// Has the verification been cancelled.
    #[napi(getter)]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Did we initiate the verification.
    #[napi(getter)]
    pub fn we_started(&self) -> bool {
        self.inner.we_started()
    }

    /// Has the verification been accepted by both sides.
    #[napi(getter)]
    pub fn has_been_accepted(&self) -> bool {
        self.inner.has_been_accepted()
    }

    /// Can the short auth string be presented to the user.
    #[napi(getter)]
    pub fn can_be_presented(&self) -> bool {
        self.inner.can_be_presented()
    }

    /// Is this a self-verification.
    #[napi(getter)]
    pub fn is_self_verification(&self) -> bool {
        self.inner.is_self_verification()
    }

    /// The other user's ID.
    #[napi(getter)]
    pub fn other_user_id(&self) -> identifiers::UserId {
        identifiers::UserId::from(self.inner.other_user_id().to_owned())
    }
}

/// A verification request.
#[napi]
pub struct VerificationRequest {
    pub(crate) inner: matrix_sdk_crypto::VerificationRequest,
}

#[napi]
impl VerificationRequest {
    /// Accept the verification request.
    ///
    /// Returns an outgoing request that needs to be sent, or `null`
    /// if the request was already accepted.
    #[napi]
    pub fn accept(
        &self,
    ) -> napi::Result<Option<Either<requests::ToDeviceRequest, requests::RoomMessageRequest>>>
    {
        self.inner.accept().map(outgoing_verification_to_napi).transpose()
    }

    /// Transition into SAS verification.
    ///
    /// Returns the outgoing request to send. After sending, use
    /// `OlmMachine.getSasVerification()` with the same user ID and
    /// flow ID to get the `Sas` object.
    ///
    /// Returns `null` if SAS could not be started.
    #[napi]
    pub async fn start_sas(
        &self,
    ) -> napi::Result<Option<Either<requests::ToDeviceRequest, requests::RoomMessageRequest>>>
    {
        match self.inner.start_sas().await.map_err(into_err)? {
            Some((_sas, request)) => Ok(Some(outgoing_verification_to_napi(request)?)),
            None => Ok(None),
        }
    }

    /// Cancel the verification request.
    #[napi]
    pub fn cancel(
        &self,
    ) -> napi::Result<Option<Either<requests::ToDeviceRequest, requests::RoomMessageRequest>>>
    {
        self.inner.cancel().map(outgoing_verification_to_napi).transpose()
    }

    /// Is the verification done.
    #[napi(getter)]
    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    /// Has the verification been cancelled.
    #[napi(getter)]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Is the request ready to start verification.
    #[napi(getter)]
    pub fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }

    /// Is the request passive (another device answered).
    #[napi(getter)]
    pub fn is_passive(&self) -> bool {
        self.inner.is_passive()
    }

    /// Did we start the request.
    #[napi(getter)]
    pub fn we_started(&self) -> bool {
        self.inner.we_started()
    }

    /// The other user's ID.
    #[napi(getter)]
    pub fn other_user_id(&self) -> identifiers::UserId {
        identifiers::UserId::from(self.inner.other_user().to_owned())
    }

    /// The room ID if this is an in-room verification.
    #[napi(getter)]
    pub fn room_id(&self) -> Option<identifiers::RoomId> {
        self.inner.room_id().map(|r| identifiers::RoomId::from(r.to_owned()))
    }

    /// The flow ID of this verification request.
    #[napi(getter)]
    pub fn flow_id(&self) -> String {
        self.inner.flow_id().as_str().to_owned()
    }
}
