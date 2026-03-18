//! Device and user identity types.

use napi_derive::*;

use crate::identifiers;

/// A Matrix device.
#[napi]
pub struct Device {
    pub(crate) inner: matrix_sdk_crypto::Device,
}

#[napi]
impl Device {
    /// The unique device ID.
    #[napi(getter)]
    pub fn device_id(&self) -> identifiers::DeviceId {
        identifiers::DeviceId::from(self.inner.device_id().to_owned())
    }

    /// The user ID of the device owner.
    #[napi(getter)]
    pub fn user_id(&self) -> identifiers::UserId {
        identifiers::UserId::from(self.inner.user_id().to_owned())
    }

    /// The human-readable name of the device, if set.
    #[napi(getter)]
    pub fn display_name(&self) -> Option<String> {
        self.inner.display_name().map(|s| s.to_owned())
    }

    /// Is this device verified (either locally trusted or cross-signing
    /// trusted).
    #[napi(getter)]
    pub fn is_verified(&self) -> bool {
        self.inner.is_verified()
    }

    /// Is this device cross-signed by its owner.
    #[napi(getter)]
    pub fn is_cross_signed_by_owner(&self) -> bool {
        self.inner.is_cross_signed_by_owner()
    }

    /// Is this device trusted via cross-signing.
    #[napi(getter)]
    pub fn is_cross_signing_trusted(&self) -> bool {
        self.inner.is_cross_signing_trusted()
    }

    /// Is this device locally trusted.
    #[napi(getter)]
    pub fn is_locally_trusted(&self) -> bool {
        self.inner.is_locally_trusted()
    }

    /// Is this device blacklisted.
    #[napi(getter)]
    pub fn is_blacklisted(&self) -> bool {
        self.inner.is_blacklisted()
    }

    /// The Curve25519 public key of this device, base64-encoded.
    #[napi(getter)]
    pub fn curve25519_key(&self) -> Option<String> {
        self.inner.curve25519_key().map(|k| k.to_base64())
    }

    /// The Ed25519 public key of this device, base64-encoded.
    #[napi(getter)]
    pub fn ed25519_key(&self) -> Option<String> {
        self.inner.ed25519_key().map(|k| k.to_base64())
    }
}

/// A user identity (own or other).
#[napi]
pub struct UserIdentity {
    pub(crate) inner: matrix_sdk_crypto::UserIdentity,
}

#[napi]
impl UserIdentity {
    /// The user ID.
    #[napi(getter)]
    pub fn user_id(&self) -> identifiers::UserId {
        identifiers::UserId::from(self.inner.user_id().to_owned())
    }

    /// Is this identity verified.
    #[napi(getter)]
    pub fn is_verified(&self) -> bool {
        self.inner.is_verified()
    }

    /// Was this identity previously verified.
    #[napi(getter)]
    pub fn was_previously_verified(&self) -> bool {
        self.inner.was_previously_verified()
    }

    /// Does this identity have a verification violation.
    #[napi(getter)]
    pub fn has_verification_violation(&self) -> bool {
        self.inner.has_verification_violation()
    }

    /// Is this our own identity.
    #[napi(getter)]
    pub fn is_own(&self) -> bool {
        matches!(self.inner, matrix_sdk_crypto::UserIdentity::Own(_))
    }
}
