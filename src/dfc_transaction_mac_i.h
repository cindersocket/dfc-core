#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool dfc_transaction_mac_input_can_add_data(
    size_t input_capacity,
    size_t input_length,
    size_t data_length);
bool dfc_transaction_mac_input_can_add_record_update(
    size_t input_capacity,
    size_t input_length,
    size_t data_length);
bool dfc_transaction_mac_input_can_add_value(size_t input_capacity, size_t input_length);
bool dfc_transaction_mac_input_can_add_clear_record(size_t input_capacity, size_t input_length);
bool dfc_transaction_mac_input_can_add_reader_id(
    size_t input_capacity,
    size_t input_length,
    bool authenticated);

bool dfc_transaction_mac_input_add_data(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length);

bool dfc_transaction_mac_input_add_record_update(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    uint32_t record_number,
    uint32_t offset,
    uint32_t length,
    const uint8_t* data,
    size_t data_length);

bool dfc_transaction_mac_input_add_value(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t command,
    uint8_t file_number,
    const uint8_t value[4]);

bool dfc_transaction_mac_input_add_reader_id(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    const uint8_t current_reader_id[16],
    const uint8_t encrypted_previous_reader_id[16]);

bool dfc_transaction_mac_input_add_clear_record(
    uint8_t* input,
    size_t input_capacity,
    size_t* input_length,
    uint8_t file_number);
