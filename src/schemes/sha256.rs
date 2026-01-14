use dashu::integer::UBig;
use solana_bn254::compression::prelude::alt_bn128_g1_decompress;

use crate::{constants::MODULUS, errors::BLSError, g1_point::G1Point};

use super::HashToCurve;

pub struct Sha256;

impl HashToCurve for Sha256 {
    fn try_hash_to_curve<T: AsRef<[u8]>>(message: T) -> Result<G1Point, BLSError> {
        (0..255)
            .find_map(|n: u8| {
                // Create a hash
                let hash = solana_nostd_sha256::hashv(&[message.as_ref(), &[n]]);

                // Convert hash to a Ubig for Bigint operations
                let hash_ubig = UBig::from_be_bytes(&hash) % &MODULUS;

                let hash_bytes = hash_ubig.to_be_bytes();
                let mut padded_bytes = [0u8; 32];
                let start = 32usize.saturating_sub(hash_bytes.len());
                padded_bytes[start..].copy_from_slice(&hash_bytes);

                // Decompress the point
                match alt_bn128_g1_decompress(&padded_bytes) {
                    Ok(p) => Some(G1Point(p)),
                    Err(_) => None,
                }
            })
            .ok_or(BLSError::HashToCurveError)
    }
}
