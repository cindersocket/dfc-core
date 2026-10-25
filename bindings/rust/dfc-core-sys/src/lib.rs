//! Raw, generated C FFI declarations for dfc-core.
//!
//! Most consumers should use the safe `dfc-core` crate. Functions in this
//! crate expose native pointers and buffer contracts directly; callers must
//! follow the ownership and lifetime rules in `ffi/dfc_ffi.h`.
#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

#[cfg(not(feature = "role-target"))]
include!("bindings.rs");

#[cfg(feature = "role-target")]
mod target;
#[cfg(feature = "role-target")]
pub use target::*;
