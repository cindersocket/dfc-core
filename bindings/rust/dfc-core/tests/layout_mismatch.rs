use dfc_core::{Credential, Error};

#[test]
fn mismatched_native_library_is_rejected_before_handles_on_every_call() {
    if std::env::var_os("DFC_EXPECT_LAYOUT_MISMATCH").is_none() {
        return;
    }

    let reject = || match Credential::decode(&[]) {
        Err(error) => error,
        Ok(_) => panic!("mismatched native library initialized"),
    };
    let first = reject();
    let second = reject();
    assert!(matches!(first, Error::LayoutMismatch { .. }));
    assert_eq!(second, first);
}
