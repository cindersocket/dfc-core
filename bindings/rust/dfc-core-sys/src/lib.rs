#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

#[cfg(not(feature = "role-target"))]
include!("bindings.rs");

#[cfg(not(feature = "role-target"))]
unsafe extern "C" {
    pub fn dfc_ffi_layout_fingerprint() -> u64;
}

#[cfg(feature = "role-target")]
mod target;
#[cfg(feature = "role-target")]
pub use target::*;
