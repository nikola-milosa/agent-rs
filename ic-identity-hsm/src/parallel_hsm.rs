use std::{fmt::Debug, path::Path, ptr, sync::Mutex};

use ic_agent::{export::Principal, identity::Delegation, Identity, Signature};
use pkcs11::{
    types::{CKM_ECDSA, CK_MECHANISM},
    Ctx,
};
use sha2::{Digest, Sha256};

use crate::{
    utils::{
        get_der_encoded_public_key, get_private_key_handle, get_slot_id, login_if_required,
        open_session, str_to_key_id,
    },
    DerPublicKeyVec, HardwareIdentityError, KeyIdVec, Sha256Hash,
};

/// An identity based on an HSM
pub struct ParallelHardwareIdentity {
    key_id: KeyIdVec,
    ctx: Ctx,
    public_key: DerPublicKeyVec,
    lock: Option<Mutex<()>>,
    slot_id: u64,
    cached_pin: String,
}

impl Debug for ParallelHardwareIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParallelHardwareIdentity")
            .field("key_id", &self.key_id)
            .field("ctx", &self.ctx)
            .field("public_key", &self.public_key)
            .field("lock", &self.lock)
            .field("slot_id", &self.slot_id)
            .field("cached_pin", &"reducted")
            .finish()
    }
}

impl ParallelHardwareIdentity {
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
        lock: Option<Mutex<()>>,
    ) -> Result<Self, HardwareIdentityError>
    where
        P: AsRef<Path>,
        PinFn: FnOnce() -> Result<String, String>,
    {
        let ctx = Ctx::new_and_initialize(pkcs11_lib_path)?;
        let slot_id = get_slot_id(&ctx, slot_index)?;
        let session_handle = open_session(&ctx, slot_id)?;
        let cached_pin = pin_fn().map_err(HardwareIdentityError::UserPinRequired)?;
        login_if_required(&ctx, session_handle, || Ok(cached_pin.clone()), slot_id)?;
        let key_id = str_to_key_id(key_id)?;
        let public_key = get_der_encoded_public_key(&ctx, session_handle, &key_id)?;
        ctx.close_session(session_handle).unwrap();

        Ok(Self {
            key_id,
            ctx,
            public_key,
            lock,
            slot_id,
            cached_pin,
        })
    }
}

impl Identity for ParallelHardwareIdentity {
    fn sender(&self) -> Result<ic_agent::export::Principal, String> {
        Ok(Principal::self_authenticating(&self.public_key))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.public_key.clone())
    }

    fn sign(
        &self,
        content: &ic_agent::agent::EnvelopeContent,
    ) -> Result<ic_agent::Signature, String> {
        self.sign_arbitrary(&content.to_request_id().signable())
    }

    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.sign_arbitrary(&content.signable())
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        let hash = Sha256::digest(content);
        let signature = match &self.lock {
            None => self.sign_hash(&hash)?,
            Some(lock) => {
                let _lock = lock.lock().map_err(|e| e.to_string())?;
                self.sign_hash(&hash)?
            }
        };

        Ok(Signature {
            public_key: self.public_key(),
            signature: Some(signature),
            delegations: None,
        })
    }
}

impl ParallelHardwareIdentity {
    fn sign_hash(&self, hash: &Sha256Hash) -> Result<Vec<u8>, String> {
        let session_handle = open_session(&self.ctx, self.slot_id).map_err(|e| e.to_string())?;
        login_if_required(
            &self.ctx,
            session_handle,
            || Ok(self.cached_pin.clone()),
            self.slot_id,
        )
        .map_err(|e| e.to_string())?;
        let private_key_handle = get_private_key_handle(&self.ctx, session_handle, &self.key_id)
            .map_err(|e| format!("Failed to get private key handle: {}", e))?;

        let mechanism = CK_MECHANISM {
            mechanism: CKM_ECDSA,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        self.ctx
            .sign_init(session_handle, &mechanism, private_key_handle)
            .map_err(|e| format!("Failed to initialize signature: {}", e))?;
        let res = self
            .ctx
            .sign(session_handle, hash)
            .map_err(|e| format!("Failed to generate signature: {}", e));

        self.ctx.close_session(session_handle).unwrap();

        res
    }
}
