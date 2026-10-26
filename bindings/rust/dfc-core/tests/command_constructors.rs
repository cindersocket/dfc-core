use dfc_core::{Command, Error};

fn frame(command: Command) -> Vec<u8> {
    let mut frame = vec![command.instruction];
    frame.extend(command.data);
    frame
}

fn decode_hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("ASCII fixture");
            u8::from_str_radix(pair, 16).expect("hex fixture")
        })
        .collect()
}

fn construct(name: &str, arguments: &str) -> Command {
    let number = || arguments.parse::<u8>().expect("numeric argument");
    match name {
        "get-version" => Command::get_version(),
        "get-free-memory" => Command::get_free_memory(),
        "format-picc" => Command::format_picc(),
        "get-key-settings" => Command::get_key_settings(),
        "get-application-ids" => Command::get_application_ids(),
        "get-df-names" => Command::get_df_names(),
        "get-file-ids" => Command::get_file_ids(),
        "get-iso-file-ids" => Command::get_iso_file_ids(),
        "get-card-uid" => Command::get_card_uid(),
        "read-signature" => Command::read_signature(number()),
        "get-key-version" => Command::get_key_version(number()),
        "select-application" => {
            let aid: [u8; 3] = decode_hex(arguments).try_into().expect("three-byte AID");
            Command::select_application(aid)
        }
        "get-file-settings" => Command::get_file_settings(number()).expect("valid file"),
        "get-file-counters" => Command::get_file_counters(number()).expect("valid file"),
        "delete-file" => Command::delete_file(number()).expect("valid file"),
        "clear-record-file" => Command::clear_record_file(number()).expect("valid file"),
        "get-value" => Command::get_value(number()).expect("valid file"),
        "read-data" => {
            let fields: Vec<u32> = arguments
                .split(',')
                .map(|field| field.parse().expect("numeric field"))
                .collect();
            Command::read_data(fields[0] as u8, fields[1], fields[2]).expect("valid range")
        }
        "write-data" | "write-record" => {
            let fields: Vec<&str> = arguments.split(',').collect();
            let file = fields[0].parse().expect("file number");
            let offset = fields[1].parse().expect("offset");
            let data = decode_hex(fields[2]);
            if name == "write-data" {
                Command::write_data(file, offset, &data).expect("valid write")
            } else {
                Command::write_record(file, offset, &data).expect("valid write")
            }
        }
        "read-records" => {
            let fields: Vec<u32> = arguments
                .split(',')
                .map(|field| field.parse().expect("numeric field"))
                .collect();
            Command::read_records(fields[0] as u8, fields[1], fields[2]).expect("valid range")
        }
        "update-record" => {
            let fields: Vec<&str> = arguments.split(',').collect();
            Command::update_record(
                fields[0].parse().expect("file number"),
                fields[1].parse().expect("record number"),
                fields[2].parse().expect("offset"),
                &decode_hex(fields[3]),
            )
            .expect("valid update")
        }
        "credit" | "debit" | "limited-credit" => {
            let fields: Vec<i32> = arguments
                .split(',')
                .map(|field| field.parse().expect("numeric field"))
                .collect();
            match name {
                "credit" => Command::credit(fields[0] as u8, fields[1]),
                "debit" => Command::debit(fields[0] as u8, fields[1]),
                _ => Command::limited_credit(fields[0] as u8, fields[1]),
            }
            .expect("valid value operation")
        }
        "commit-transaction" => Command::commit_transaction((!arguments.is_empty()).then(number)),
        "abort-transaction" => Command::abort_transaction(),
        _ => panic!("unknown constructor {name}"),
    }
}

#[test]
fn constructors_match_shared_vectors() {
    let vectors = include_str!("../../../../tests/command-constructor-vectors.txt");
    for line in vectors
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.split('|');
        let name = fields.next().expect("name");
        let arguments = fields.next().expect("arguments");
        let expected = decode_hex(fields.next().expect("frame"));
        assert_eq!(frame(construct(name, arguments)), expected, "{name}");
    }
}

#[test]
fn file_constructors_reject_out_of_range_numbers() {
    for constructor in [
        Command::get_file_settings,
        Command::get_file_counters,
        Command::delete_file,
        Command::clear_record_file,
        Command::get_value,
    ] {
        assert!(matches!(constructor(32), Err(Error::InvalidArgument)));
    }
    assert!(matches!(
        Command::read_data(32, 0, 1),
        Err(Error::InvalidArgument)
    ));
    assert!(matches!(
        Command::write_data(32, 0, b"x"),
        Err(Error::InvalidArgument)
    ));
    assert!(matches!(
        Command::credit(32, 1),
        Err(Error::InvalidArgument)
    ));
}

#[test]
fn payload_boundaries_match_shared_vectors() {
    let vectors = include_str!("../../../../tests/command-constructor-boundaries.txt");
    for line in vectors
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.split('|');
        let name = fields.next().expect("constructor");
        let length = fields
            .next()
            .expect("length")
            .parse()
            .expect("numeric length");
        let expected = fields.next().expect("expected result");
        let data = vec![0; length];
        let result = match name {
            "write-data" => Command::write_data(1, 0, &data),
            "write-record" => Command::write_record(1, 0, &data),
            "update-record" => Command::update_record(1, 0, 0, &data),
            _ => panic!("unknown constructor {name}"),
        };
        assert_eq!(result.is_ok(), expected == "accept", "{name} {length}");
    }
}
