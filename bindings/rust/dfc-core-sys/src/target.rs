use core::ffi::c_void;

#[repr(C)]
/// Opaque target-role virtual-card handle.
pub struct DfcTargetPicc {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Size and alignment required for caller-managed native storage.
pub struct DfcTargetLayout {
    /// Required storage size in bytes.
    pub size: usize,
    /// Required storage alignment in bytes.
    pub alignment: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Activation data returned by the target-role virtual card.
pub struct DfcTargetActivation {
    /// Number of valid UID bytes.
    pub uid_len: usize,
    /// Number of valid ATS bytes.
    pub ats_len: usize,
    /// Number of valid ATQA bytes.
    pub atqa_len: usize,
    /// Number of valid protocol bytes.
    pub protocol_len: usize,
    /// Number of valid RF-detail bytes.
    pub rf_detail_len: usize,
    /// UID storage; use only `uid_len` bytes.
    pub uid: [u8; 10],
    /// ATS storage; use only `ats_len` bytes.
    pub ats: [u8; 20],
    /// ATQA storage; use only `atqa_len` bytes.
    pub atqa: [u8; 2],
    /// SAK byte.
    pub sak: u8,
    /// Protocol storage; use only `protocol_len` bytes.
    pub protocol: [u8; 2],
    /// RF-detail storage; use only `rf_detail_len` bytes.
    pub rf_detail: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
/// Public target-role virtual-card state snapshot.
pub struct DfcTargetSnapshot {
    /// Selection state: `0` for none, `1` for the PICC, or `2` for an application.
    pub selected: u32,
    /// Selected model application index, valid only when `selected == 2`.
    pub selected_application_index: u32,
    /// Current EV2 command counter, valid only when `ev2_active != 0`.
    pub ev2_command_counter: u32,
    /// Selected AID in model byte order (most-significant byte first), valid
    /// only when `selected == 2`.
    pub selected_aid: [u8; 3],
    /// Whether credential state has unpersisted changes.
    pub dirty: u8,
    /// Authentication state: `0` when unauthenticated, otherwise the native
    /// authentication instruction byte that established the session.
    pub auth_mode: u8,
    /// Active native authentication key number, valid only when `auth_mode != 0`.
    pub auth_key_no: u8,
    /// Whether an EV2 session is active.
    pub ev2_active: u8,
    /// Active EV2 key number, valid only when `ev2_active != 0`.
    pub ev2_key_no: u8,
    /// Whether virtual-card selection completed.
    pub virtual_card_selected: u8,
    /// Whether proximity verification completed.
    pub proximity_verified: u8,
}

unsafe extern "C" {
    /// Returns the required storage layout for one target credential.
    pub fn dfc_target_credential_layout() -> DfcTargetLayout;

    /// Initializes credential storage returned by [`dfc_target_credential_layout`].
    ///
    /// # Safety
    ///
    /// `storage` must point to writable memory with at least the reported size
    /// and alignment. The same storage must be initialized only once before it
    /// is passed to another credential function.
    pub fn dfc_target_credential_init(storage: *mut c_void);

    /// Wipes and destroys an initialized target credential.
    ///
    /// # Safety
    ///
    /// `storage` must identify a live credential initialized by
    /// [`dfc_target_credential_init`] or left initialized by any
    /// [`dfc_target_credential_decode`] attempt. It must be destroyed exactly
    /// once and must not still be borrowed by a live target virtual card.
    pub fn dfc_target_credential_destroy(storage: *mut c_void);

    /// Decodes binary credential bytes into zeroed or initialized storage.
    ///
    /// # Safety
    ///
    /// `storage` must identify writable storage with the layout returned by
    /// [`dfc_target_credential_layout`]. It must either be entirely zeroed or
    /// initialized by [`dfc_target_credential_init`]. `content` must be readable
    /// for `len` bytes. The input may overlap neither the credential storage nor
    /// memory the credential owns. After this call, `storage` is initialized and
    /// must be destroyed exactly once, including when decoding fails.
    pub fn dfc_target_credential_decode(
        storage: *mut c_void,
        content: *const u8,
        len: usize,
    ) -> i32;

    /// Validates a decoded target credential.
    ///
    /// # Safety
    ///
    /// `storage` must identify a live initialized credential and remain valid
    /// for the duration of the call.
    pub fn dfc_target_credential_validate(storage: *const c_void) -> i32;

    /// Encodes a target credential into caller-owned output storage.
    ///
    /// # Safety
    ///
    /// `storage` must identify a live initialized credential and `len` must be
    /// writable. When `capacity` is nonzero, `out` must be writable for that
    /// many bytes and must not overlap the credential. A null `out` is allowed
    /// only with zero capacity to query the required length through `len`.
    pub fn dfc_target_credential_encode(
        storage: *const c_void,
        out: *mut u8,
        capacity: usize,
        len: *mut usize,
    ) -> i32;

    /// Returns the required storage layout for one target virtual card.
    pub fn dfc_target_picc_layout() -> DfcTargetLayout;

    /// Initializes a target virtual card over caller-managed storage.
    ///
    /// # Safety
    ///
    /// `picc_storage` must point to writable memory with the size and alignment
    /// returned by [`dfc_target_picc_layout`]. `credential_storage` must identify
    /// a live, validated target credential. `out` must be writable. The
    /// credential and both backing allocations must remain alive and unmoved
    /// until [`dfc_target_picc_destroy`] returns.
    pub fn dfc_target_picc_init(
        picc_storage: *mut c_void,
        credential_storage: *mut c_void,
        out: *mut *mut DfcTargetPicc,
    ) -> i32;

    /// Wipes and destroys an initialized target virtual card.
    ///
    /// # Safety
    ///
    /// `picc` must be the live handle returned by [`dfc_target_picc_init`]. It
    /// must be destroyed exactly once before either backing allocation or the
    /// retained credential is released.
    pub fn dfc_target_picc_destroy(picc: *mut DfcTargetPicc);

    /// Starts a new activation and writes its transport parameters.
    ///
    /// # Safety
    ///
    /// `picc` must be a live initialized handle and `out` must point to writable
    /// storage for one [`DfcTargetActivation`].
    pub fn dfc_target_picc_activate(picc: *mut DfcTargetPicc, out: *mut DfcTargetActivation)
    -> i32;

    /// Exchanges one complete command with a target virtual card.
    ///
    /// # Safety
    ///
    /// `picc` must be live. `command` must be readable for `command_len` bytes,
    /// `response_len` must be writable, and `response` must be writable for
    /// `response_capacity` bytes. Command and response ranges must not overlap.
    /// On a short output buffer, `response_len` receives the required length.
    pub fn dfc_target_picc_exchange(
        picc: *mut DfcTargetPicc,
        command: *const u8,
        command_len: usize,
        response: *mut u8,
        response_capacity: usize,
        response_len: *mut usize,
    ) -> i32;

    /// Exchanges one ISO-DEP frame with a target virtual card.
    ///
    /// # Safety
    ///
    /// `picc` must be live. `frame` must be readable for `frame_len` bytes,
    /// `response_len` must be writable, and `response` must be writable for
    /// `response_capacity` bytes. Input and output ranges must not overlap. On
    /// a short output buffer, `response_len` receives the required length.
    pub fn dfc_target_picc_frame_exchange(
        picc: *mut DfcTargetPicc,
        frame: *const u8,
        frame_len: usize,
        response: *mut u8,
        response_capacity: usize,
        response_len: *mut usize,
    ) -> i32;

    /// Ends the RF field and clears protocol state.
    ///
    /// # Safety
    ///
    /// `picc` must be a live initialized target virtual-card handle.
    pub fn dfc_target_picc_field_off(picc: *mut DfcTargetPicc) -> i32;

    /// Resets protocol state while retaining the credential.
    ///
    /// # Safety
    ///
    /// `picc` must be a live initialized target virtual-card handle.
    pub fn dfc_target_picc_reset_protocol(picc: *mut DfcTargetPicc) -> i32;

    /// Advances the target virtual card clock in milliseconds.
    ///
    /// # Safety
    ///
    /// `picc` must be a live initialized target virtual-card handle.
    pub fn dfc_target_picc_advance_time(picc: *mut DfcTargetPicc, elapsed_milliseconds: u32)
    -> i32;

    /// Writes a public state snapshot.
    ///
    /// # Safety
    ///
    /// `picc` must be live and `out` must point to writable storage for one
    /// [`DfcTargetSnapshot`].
    pub fn dfc_target_picc_snapshot(picc: *const DfcTargetPicc, out: *mut DfcTargetSnapshot)
    -> i32;

    /// Marks current credential state as persisted.
    ///
    /// # Safety
    ///
    /// `picc` must be a live initialized target virtual-card handle.
    pub fn dfc_target_picc_mark_persisted(picc: *mut DfcTargetPicc) -> i32;
}
