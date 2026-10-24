use dfc_core::Credential;

#[test]
fn legacy_random_id_prefix_round_trips() {
    let mut credential = Credential::load(include_bytes!(
        "../../../../examples/credentials/v6-minimal.dfc"
    ))
    .expect("load fixture");
    let mut picc = credential.picc_settings().expect("read PICC settings");
    picc.random_id = 1;
    picc.random_id_legacy = 1;
    credential
        .set_picc_settings(&picc)
        .expect("set PICC settings");
    credential.finish().expect("validate credential");

    let encoded = credential.encode().expect("encode credential");
    let decoded = Credential::decode(&encoded).expect("decode credential");
    let decoded_picc = decoded.picc_settings().expect("read decoded PICC settings");
    assert_eq!(decoded_picc.random_id, 1);
    assert_eq!(decoded_picc.random_id_legacy, 1);
}
