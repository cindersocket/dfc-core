use dfc_core::{Command, Error, iso_append_record_apdu, parse_iso7816_response};

#[test]
fn iso_append_record_helpers_preserve_two_byte_status() {
    for line in include_str!("fixtures/iso7816-helper-vectors.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<&str> = line.split('|').collect();
        let input = decode_hex(fields[1]);
        if fields[0] == "append-record" {
            assert_eq!(
                iso_append_record_apdu(fields[2].parse().expect("SFI"), &input)
                    .expect("valid APPEND RECORD"),
                decode_hex(fields[3])
            );
        } else {
            assert_eq!(fields[0], "parse-response");
            let (data, status) = parse_iso7816_response(&input).expect("valid response");
            assert_eq!(data, decode_hex(fields[2]));
            assert_eq!(
                status,
                u16::from_str_radix(fields[3], 16).expect("status word")
            );
        }
    }
}

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
        "read-data" | "read-data-iso-chaining" => {
            let fields: Vec<u32> = arguments
                .split(',')
                .map(|field| field.parse().expect("numeric field"))
                .collect();
            if name == "read-data-iso-chaining" {
                Command::read_data_iso_chaining(fields[0] as u8, fields[1], fields[2])
                    .expect("valid range")
            } else {
                Command::read_data(fields[0] as u8, fields[1], fields[2]).expect("valid range")
            }
        }
        "write-data" | "write-data-iso-chaining" | "write-record" | "write-record-iso-chaining" => {
            let fields: Vec<&str> = arguments.split(',').collect();
            let file = fields[0].parse().expect("file number");
            let offset = fields[1].parse().expect("offset");
            let data = decode_hex(fields[2]);
            match name {
                "write-data" => Command::write_data(file, offset, &data),
                "write-data-iso-chaining" => Command::write_data_iso_chaining(file, offset, &data),
                "write-record" => Command::write_record(file, offset, &data),
                _ => Command::write_record_iso_chaining(file, offset, &data),
            }
            .expect("valid write")
        }
        "read-records" | "read-records-iso-chaining" => {
            let fields: Vec<u32> = arguments
                .split(',')
                .map(|field| field.parse().expect("numeric field"))
                .collect();
            if name == "read-records-iso-chaining" {
                Command::read_records_iso_chaining(fields[0] as u8, fields[1], fields[2])
                    .expect("valid range")
            } else {
                Command::read_records(fields[0] as u8, fields[1], fields[2]).expect("valid range")
            }
        }
        "update-record" | "update-record-iso-chaining" => {
            let fields: Vec<&str> = arguments.split(',').collect();
            let file = fields[0].parse().expect("file number");
            let record = fields[1].parse().expect("record number");
            let offset = fields[2].parse().expect("offset");
            let data = decode_hex(fields[3]);
            if name == "update-record-iso-chaining" {
                Command::update_record_iso_chaining(file, record, offset, &data)
            } else {
                Command::update_record(file, record, offset, &data)
            }
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
    let vectors = include_str!("fixtures/command-constructor-vectors.txt");
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
    let vectors = include_str!("fixtures/command-constructor-boundaries.txt");
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
