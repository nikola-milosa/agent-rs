use pkcs11::{
    types::{
        CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE, CKF_LOGIN_REQUIRED,
        CKF_SERIAL_SESSION, CKK_ECDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKU_USER, CK_ATTRIBUTE,
        CK_ATTRIBUTE_TYPE, CK_KEY_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE,
        CK_SLOT_ID,
    },
    Ctx,
};
use simple_asn1::{
    from_der, oid, to_der,
    ASN1Block::{BitString, ObjectIdentifier, OctetString, Sequence},
};

use crate::{DerPublicKeyVec, HardwareIdentityError, KeyId, KeyIdVec, EXPECTED_EC_PARAMS};

pub fn get_slot_id(ctx: &Ctx, slot_index: usize) -> Result<CK_SLOT_ID, HardwareIdentityError> {
    ctx.get_slot_list(true)?
        .get(slot_index)
        .ok_or(HardwareIdentityError::NoSuchSlotIndex(slot_index))
        .map(|x| *x)
}

// We open a session for the duration of the lifetime of the HardwareIdentity.
pub fn open_session(
    ctx: &Ctx,
    slot_id: CK_SLOT_ID,
) -> Result<CK_SESSION_HANDLE, HardwareIdentityError> {
    let flags = CKF_SERIAL_SESSION;
    let application = None;
    let notify = None;
    let session_handle = ctx.open_session(slot_id, flags, application, notify)?;
    Ok(session_handle)
}

// We might need to log in.  This requires the PIN.
pub fn login_if_required<PinFn>(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    pin_fn: PinFn,
    slot_id: CK_SLOT_ID,
) -> Result<bool, HardwareIdentityError>
where
    PinFn: FnOnce() -> Result<String, String>,
{
    let token_info = ctx.get_token_info(slot_id)?;
    let login_required = token_info.flags & CKF_LOGIN_REQUIRED != 0;

    if login_required {
        let pin = pin_fn().map_err(HardwareIdentityError::UserPinRequired)?;
        ctx.login(session_handle, CKU_USER, Some(&pin))?;
    }
    Ok(login_required)
}

// Return the DER-encoded public key in the expected format.
// We also validate that it's an ECDSA key on the correct curve.
pub fn get_der_encoded_public_key(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
) -> Result<DerPublicKeyVec, HardwareIdentityError> {
    let object_handle = get_public_key_handle(ctx, session_handle, key_id)?;

    validate_key_type(ctx, session_handle, object_handle)?;
    validate_ec_params(ctx, session_handle, object_handle)?;

    let ec_point = get_ec_point(ctx, session_handle, object_handle)?;

    let oid_ecdsa = oid!(1, 2, 840, 10045, 2, 1);
    let oid_curve_secp256r1 = oid!(1, 2, 840, 10045, 3, 1, 7);
    let ec_param = Sequence(
        0,
        vec![
            ObjectIdentifier(0, oid_ecdsa),
            ObjectIdentifier(0, oid_curve_secp256r1),
        ],
    );
    let ec_point = BitString(0, ec_point.len() * 8, ec_point);
    let public_key = Sequence(0, vec![ec_param, ec_point]);
    let der = to_der(&public_key)?;
    Ok(der)
}

// Ensure that the key type is ECDSA.
pub fn validate_key_type(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<(), HardwareIdentityError> {
    // The call to ctx.get_attribute_value() will mutate kt!
    // with_ck_ulong` stores &kt as a mutable pointer by casting it to CK_VOID_PTR, which is:
    //      pub type CK_VOID_PTR = *mut CK_VOID;
    // `let mut kt...` here emits a warning, unfortunately.
    let kt: CK_KEY_TYPE = 0;

    let mut attribute_types = vec![CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&kt)];
    ctx.get_attribute_value(session_handle, object_handle, &mut attribute_types)?;
    if kt != CKK_ECDSA {
        Err(HardwareIdentityError::UnexpectedKeyType(kt))
    } else {
        Ok(())
    }
}

// We just want to make sure that we are using the expected EC curve prime256v1 (secp256r1),
// since the HSMs also support things like secp384r1 and secp512r1.
pub fn validate_ec_params(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<(), HardwareIdentityError> {
    let ec_params = get_ec_params(ctx, session_handle, object_handle)?;
    if ec_params != EXPECTED_EC_PARAMS {
        Err(HardwareIdentityError::InvalidEcParams {
            expected: EXPECTED_EC_PARAMS.to_vec(),
            actual: ec_params,
        })
    } else {
        Ok(())
    }
}

// Obtain the EcPoint, which is an (x,y) coordinate.  Each coordinate is 32 bytes.
// These are preceded by an 04 byte meaning "uncompressed point."
// The returned vector will therefore have len=65.
pub fn get_ec_point(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    let der_encoded_ec_point =
        get_variable_length_attribute(ctx, session_handle, object_handle, CKA_EC_POINT)?;

    let blocks =
        from_der(der_encoded_ec_point.as_slice()).map_err(HardwareIdentityError::ASN1Decode)?;
    let block = blocks.get(0).ok_or(HardwareIdentityError::EcPointEmpty)?;
    if let OctetString(_size, data) = block {
        Ok(data.clone())
    } else {
        Err(HardwareIdentityError::ExpectedEcPointOctetString)
    }
}

// In order to read a variable-length attribute, we need to first read its length.
pub fn get_attribute_length(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<usize, HardwareIdentityError> {
    let mut attributes = vec![CK_ATTRIBUTE::new(attribute_type)];
    ctx.get_attribute_value(session_handle, object_handle, &mut attributes)?;

    let first = attributes
        .get(0)
        .ok_or(HardwareIdentityError::AttributeNotFound(attribute_type))?;
    Ok(first.ulValueLen as usize)
}

// Get a variable-length attribute, by first reading its length and then the value.
pub fn get_variable_length_attribute(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
    attribute_type: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    let length = get_attribute_length(ctx, session_handle, object_handle, attribute_type)?;
    let value = vec![0; length];

    let mut attrs = vec![CK_ATTRIBUTE::new(attribute_type).with_bytes(value.as_slice())];
    ctx.get_attribute_value(session_handle, object_handle, &mut attrs)?;
    Ok(value)
}

pub fn get_ec_params(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    object_handle: CK_OBJECT_HANDLE,
) -> Result<Vec<u8>, HardwareIdentityError> {
    get_variable_length_attribute(ctx, session_handle, object_handle, CKA_EC_PARAMS)
}

pub fn get_public_key_handle(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    get_object_handle_for_key(ctx, session_handle, key_id, CKO_PUBLIC_KEY)
}

pub fn get_private_key_handle(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    get_object_handle_for_key(ctx, session_handle, key_id, CKO_PRIVATE_KEY)
}

// Find a public or private key.
pub fn get_object_handle_for_key(
    ctx: &Ctx,
    session_handle: CK_SESSION_HANDLE,
    key_id: &KeyId,
    object_class: CK_OBJECT_CLASS,
) -> Result<CK_OBJECT_HANDLE, HardwareIdentityError> {
    let attributes = [
        CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_id),
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&object_class),
    ];
    ctx.find_objects_init(session_handle, &attributes)?;
    let object_handles = ctx.find_objects(session_handle, 1)?;
    let object_handle = *object_handles
        .first()
        .ok_or(HardwareIdentityError::KeyNotFound)?;
    ctx.find_objects_final(session_handle)?;
    Ok(object_handle)
}

// A key id is a sequence of pairs of hex digits, case-insensitive.
pub fn str_to_key_id(s: &str) -> Result<KeyIdVec, HardwareIdentityError> {
    let bytes = hex::decode(s)?;
    Ok(bytes)
}
