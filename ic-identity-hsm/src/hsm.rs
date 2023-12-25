use ic_agent::{
    agent::EnvelopeContent, export::Principal, identity::Delegation, Identity, Signature,
};

use pkcs11::{
    types::{CKM_ECDSA, CK_MECHANISM, CK_SESSION_HANDLE},
    Ctx,
};
use sha2::{Digest, Sha256};
use std::{path::Path, ptr};

use crate::{
    utils::{
        get_der_encoded_public_key, get_private_key_handle, get_slot_id, login_if_required,
        open_session, str_to_key_id,
    },
    DerPublicKeyVec, HardwareIdentityError, KeyIdVec, Sha256Hash,
};

/// An identity based on an HSM
#[derive(Debug)]
pub struct HardwareIdentity {
    key_id: KeyIdVec,
    ctx: Ctx,
    session_handle: CK_SESSION_HANDLE,
    logged_in: bool,
    public_key: DerPublicKeyVec,
}

impl HardwareIdentity {
    /// Create an identity using a specific key on an HSM.
    /// The filename will be something like /usr/local/lib/opensc-pkcs11.s
    /// The key_id must refer to a ECDSA key with parameters prime256v1 (secp256r1)
    /// The key must already have been created.  You can create one with pkcs11-tool:
    /// $ pkcs11-tool -k --slot $SLOT -d $KEY_ID --key-type EC:prime256v1 --pin $PIN
    pub fn new<P, PinFn>(
        pkcs11_lib_path: P,
        slot_index: usize,
        key_id: &str,
        pin_fn: PinFn,
    ) -> Result<HardwareIdentity, HardwareIdentityError>
    where
        P: AsRef<Path>,
        PinFn: FnOnce() -> Result<String, String>,
    {
        let ctx = Ctx::new_and_initialize(pkcs11_lib_path)?;
        let slot_id = get_slot_id(&ctx, slot_index)?;
        let session_handle = open_session(&ctx, slot_id)?;
        let logged_in = login_if_required(&ctx, session_handle, pin_fn, slot_id)?;
        let key_id = str_to_key_id(key_id)?;
        let public_key = get_der_encoded_public_key(&ctx, session_handle, &key_id)?;

        Ok(HardwareIdentity {
            key_id,
            ctx,
            session_handle,
            logged_in,
            public_key,
        })
    }
}

impl Identity for HardwareIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.public_key))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.public_key.clone())
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.sign_arbitrary(&content.to_request_id().signable())
    }

    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.sign_arbitrary(&content.signable())
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        let hash = Sha256::digest(content);
        let signature = self.sign_hash(&hash)?;

        Ok(Signature {
            public_key: self.public_key(),
            signature: Some(signature),
            delegations: None,
        })
    }
}

impl HardwareIdentity {
    fn sign_hash(&self, hash: &Sha256Hash) -> Result<Vec<u8>, String> {
        let private_key_handle =
            get_private_key_handle(&self.ctx, self.session_handle, &self.key_id)
                .map_err(|e| format!("Failed to get private key handle: {}", e))?;

        let mechanism = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        self.ctx
            .sign_init(self.session_handle, &mechanism, private_key_handle)
            .map_err(|e| format!("Failed to initialize signature: {}", e))?;
        self.ctx
            .sign(self.session_handle, hash)
            .map_err(|e| format!("Failed to generate signature: {}", e))
    }
}

impl Drop for HardwareIdentity {
    fn drop(&mut self) {
        if self.logged_in {
            // necessary? probably not
            self.ctx.logout(self.session_handle).unwrap();
        }
        self.ctx.close_session(self.session_handle).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::hsm::str_to_key_id;

    #[test]
    fn key_id_conversion() {
        let key_id_v = str_to_key_id("a53f61e3").unwrap();
        assert_eq!(key_id_v, vec![0xa5, 0x3f, 0x61, 0xe3]);
    }
}
