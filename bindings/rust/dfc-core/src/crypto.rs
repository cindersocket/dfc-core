use alloc::vec;
use alloc::vec::Vec;

use dfc_core_sys as sys;

use crate::{Error, ensure_abi, status};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DiversificationAlgorithm {
    Aes128 = 0,
    Tdea2 = 1,
    Tdea3 = 2,
}

pub fn diversify_key(
    algorithm: DiversificationAlgorithm,
    master_key: &[u8],
    diversification_input: &[u8],
) -> Result<Vec<u8>, Error> {
    ensure_abi()?;
    let length = match algorithm {
        DiversificationAlgorithm::Aes128 | DiversificationAlgorithm::Tdea2 => 16,
        DiversificationAlgorithm::Tdea3 => 24,
    };
    let mut output = vec![0; length];
    let mut produced = 0;
    status(unsafe {
        sys::dfc_ffi_an10922_diversify(
            algorithm as u32,
            master_key.as_ptr(),
            master_key.len(),
            diversification_input.as_ptr(),
            diversification_input.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut produced,
        )
    })?;
    output.truncate(produced);
    Ok(output)
}
