//! A crate to manage identities related to HSM (Hardware Security Module),
//! allowing users to sign Internet Computer messages with their hardware key.
//! Also supports SoftHSM.
//!
//! # Example
//!
//! ```rust,no_run
//! use ic_agent::agent::{Agent, http_transport::ReqwestTransport};
//! use ic_identity_hsm::HardwareIdentity;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let replica_url = "";
//! # let lib_path = "";
//! # let slot_index = 0;
//! # let key_id = "";
//! let agent = Agent::builder()
//!     .with_transport(ReqwestTransport::create(replica_url)?)
//!     .with_identity(HardwareIdentity::new(lib_path, slot_index, key_id, || Ok("hunter2".to_string()))?)
//!     .build();
//! # Ok(())
//! # }

#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]

pub(crate) mod hsm;
pub(crate) mod parallel_hsm;
pub(crate) mod utils;
pub use hsm::HardwareIdentity;
pub use parallel_hsm::ParallelHardwareIdentity;
use pkcs11::types::{CK_ATTRIBUTE_TYPE, CK_KEY_TYPE};
use sha2::{
    digest::{generic_array::GenericArray, OutputSizeUser},
    Sha256,
};
use simple_asn1::{ASN1DecodeErr, ASN1EncodeErr};
use thiserror::Error;

pub(crate) type KeyIdVec = Vec<u8>;
pub(crate) type KeyId = [u8];

pub(crate) type DerPublicKeyVec = Vec<u8>;

/// Type alias for a sha256 result (ie. a u256).
pub(crate) type Sha256Hash = GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>;

// We expect the parameters to be curve secp256r1.  This is the base127 encoded form:
pub(crate) const EXPECTED_EC_PARAMS: &[u8; 10] = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

/// An error happened related to a HardwareIdentity.
#[derive(Error, Debug)]
pub enum HardwareIdentityError {
    /// A PKCS11 error occurred.
    #[error(transparent)]
    PKCS11(#[from] pkcs11::errors::Error),

    // ASN1DecodeError does not implement the Error trait and so we cannot use #[from]
    /// An error occurred when decoding ASN1.
    #[error("ASN decode error {0}")]
    ASN1Decode(ASN1DecodeErr),

    /// An error occurred when encoding ASN1.
    #[error(transparent)]
    ASN1Encode(#[from] ASN1EncodeErr),

    /// An error occurred when decoding a key ID.
    #[error(transparent)]
    KeyIdDecode(#[from] hex::FromHexError),

    /// The key was not found.
    #[error("Key not found")]
    KeyNotFound,

    /// An unexpected key type was found.
    #[error("Unexpected key type {0}")]
    UnexpectedKeyType(CK_KEY_TYPE),

    /// An EcPoint block was expected to be an OctetString, but was not.
    #[error("Expected EcPoint to be an OctetString")]
    ExpectedEcPointOctetString,

    /// An EcPoint block was unexpectedly empty.
    #[error("EcPoint is empty")]
    EcPointEmpty,

    /// The attribute with the specified type was not found.
    #[error("Attribute with type={0} not found")]
    AttributeNotFound(CK_ATTRIBUTE_TYPE),

    /// The EcParams given were not the ones the crate expected.
    #[error("Invalid EcParams.  Expected prime256v1 {:02x?}, actual is {:02x?}", .expected, .actual)]
    InvalidEcParams {
        /// The expected value of the EcParams.
        expected: Vec<u8>,
        /// The actual value of the EcParams.
        actual: Vec<u8>,
    },

    /// The PIN login function returned an error, but PIN login was required.
    #[error("User PIN is required: {0}")]
    UserPinRequired(String),

    /// A slot index was provided that does not exist.
    #[error("No such slot index ({0}")]
    NoSuchSlotIndex(usize),
}
