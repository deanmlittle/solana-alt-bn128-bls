use dashu::integer::UBig;
use solana_bn254::compression::prelude::alt_bn128_g1_decompress;

use crate::{constants::MODULUS, errors::BLSError, g1_point::G1Point};

use super::HashToCurve;

/// The last multiple of the modulus before 2^256 used to normalize
/// hash values for our signing scheme.
///
/// 0xf1f5883e65f820d099915c908786b9d3f58714d70a38f4c22ca2bc723a70f263
pub static NORMALIZE_MODULUS: UBig = unsafe {
    UBig::from_static_words(&[
        0x2ca2bc723a70f263,
        0xf58714d70a38f4c2,
        0x99915c908786b9d3,
        0xf1f5883e65f820d0,
    ])
};

pub struct Sha256Normalized;

impl HashToCurve for Sha256Normalized {
    fn try_hash_to_curve<T: AsRef<[u8]>>(message: T) -> Result<G1Point, BLSError> {
        (0..255)
            .find_map(|n: u8| {
                // Create a hash
                let hash = solana_nostd_sha256::hashv(&[message.as_ref(), &[n]]);

                // Convert hash to a Ubig for Bigint operations
                let hash_ubig = UBig::from_be_bytes(&hash);

                // Check if the hash is higher than our normalization modulus of Fq * 5
                if hash_ubig >= NORMALIZE_MODULUS {
                    return None;
                }

                let modulus_ubig = hash_ubig % &MODULUS;

                let modulus_bytes = modulus_ubig.to_be_bytes();
                let mut padded_bytes = [0u8; 32];
                let start = 32usize.saturating_sub(modulus_bytes.len());
                padded_bytes[start..].copy_from_slice(&modulus_bytes);

                // Decompress the point
                match alt_bn128_g1_decompress(&padded_bytes) {
                    Ok(p) => Some(G1Point(p)),
                    Err(_) => None,
                }
            })
            .ok_or(BLSError::HashToCurveError)
    }
}
