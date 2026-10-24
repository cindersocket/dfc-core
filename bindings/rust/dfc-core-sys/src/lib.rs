#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

#[cfg(not(feature = "role-target"))]
include!("bindings.rs");

#[cfg(feature = "role-target")]
mod target;
#[cfg(feature = "role-target")]
pub use target::*;
