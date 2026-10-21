use core::ffi::c_void;

#[repr(C)]
pub struct DfcTargetPicc {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DfcTargetLayout {
    pub size: usize,
    pub alignment: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DfcTargetActivation {
    pub uid_len: usize,
    pub ats_len: usize,
    pub atqa_len: usize,
    pub protocol_len: usize,
    pub rf_detail_len: usize,
    pub uid: [u8; 10],
    pub ats: [u8; 20],
    pub atqa: [u8; 2],
    pub sak: u8,
    pub protocol: [u8; 2],
    pub rf_detail: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DfcTargetSnapshot {
    pub selected: u32,
    pub selected_application_index: u32,
    pub ev2_command_counter: u32,
    pub selected_aid: [u8; 3],
    pub dirty: u8,
    pub auth_mode: u8,
    pub auth_key_no: u8,
    pub ev2_active: u8,
    pub ev2_key_no: u8,
    pub ev2_transaction_identifier: [u8; 4],
    pub ev2_encryption_key: [u8; 16],
    pub ev2_mac_key: [u8; 16],
    pub virtual_card_selected: u8,
    pub proximity_verified: u8,
}

unsafe extern "C" {
    pub fn dfc_target_credential_layout() -> DfcTargetLayout;
    pub fn dfc_target_credential_init(storage: *mut c_void);
    pub fn dfc_target_credential_destroy(storage: *mut c_void);
    pub fn dfc_target_credential_decode(
        storage: *mut c_void,
        content: *const u8,
        len: usize,
    ) -> i32;
    pub fn dfc_target_credential_validate(storage: *const c_void) -> i32;
    pub fn dfc_target_credential_encode(
        storage: *const c_void,
        out: *mut u8,
        capacity: usize,
        len: *mut usize,
    ) -> i32;
    pub fn dfc_target_picc_layout() -> DfcTargetLayout;
    pub fn dfc_target_picc_init(
        picc_storage: *mut c_void,
        credential_storage: *mut c_void,
        out: *mut *mut DfcTargetPicc,
    ) -> i32;
    pub fn dfc_target_picc_destroy(picc: *mut DfcTargetPicc);
    pub fn dfc_target_picc_activate(picc: *mut DfcTargetPicc, out: *mut DfcTargetActivation)
    -> i32;
    pub fn dfc_target_picc_exchange(
        picc: *mut DfcTargetPicc,
        command: *const u8,
        command_len: usize,
        response: *mut u8,
        response_capacity: usize,
        response_len: *mut usize,
    ) -> i32;
    pub fn dfc_target_picc_frame_exchange(
        picc: *mut DfcTargetPicc,
        frame: *const u8,
        frame_len: usize,
        response: *mut u8,
        response_capacity: usize,
        response_len: *mut usize,
    ) -> i32;
    pub fn dfc_target_picc_field_off(picc: *mut DfcTargetPicc) -> i32;
    pub fn dfc_target_picc_reset_protocol(picc: *mut DfcTargetPicc) -> i32;
    pub fn dfc_target_picc_advance_time(picc: *mut DfcTargetPicc, elapsed_milliseconds: u32)
    -> i32;
    pub fn dfc_target_picc_snapshot(picc: *const DfcTargetPicc, out: *mut DfcTargetSnapshot)
    -> i32;
    pub fn dfc_target_picc_mark_persisted(picc: *mut DfcTargetPicc) -> i32;
}
