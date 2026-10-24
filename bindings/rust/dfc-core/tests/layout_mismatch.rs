use dfc_core::{Credential, Error};

#[test]
fn mismatched_native_library_is_rejected_before_handles_on_every_call() {
    assert_eq!(
        std::env::var("DFC_EXPECT_LAYOUT_MISMATCH").as_deref(),
        Ok("1"),
        "layout mismatch test requires DFC_EXPECT_LAYOUT_MISMATCH=1",
    );

    let reject = || match Credential::decode(&[]) {
        Err(error) => error,
        Ok(_) => panic!("mismatched native library initialized"),
    };
    let first = reject();
    let second = reject();
    assert!(matches!(first, Error::LayoutMismatch { .. }));
    assert_eq!(second, first);
}
