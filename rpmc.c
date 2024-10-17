/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2024 Matti Finder
 * (written by Matti Finder <matti.finder@gmail.com>)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "rpmc.h"
#include "flash.h"
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#define RPMC_OP1_MSG_HEADER_LENGTH 4
#define RPMC_SIGNATURE_LENGTH 32
#define RPMC_COUNTER_LENGTH 4
#define RPMC_KEY_DATA_LENGTH 4
#define RPMC_TAG_LENGTH 12
#define RPMC_HMAC_KEY_LENGTH 32
#define RPMC_TRUNCATED_SIG_LENGTH 28

// OP1 commands
#define RPMC_WRITE_ROOT_KEY_MSG_LENGTH (RPMC_OP1_MSG_HEADER_LENGTH + RPMC_HMAC_KEY_LENGTH + RPMC_TRUNCATED_SIG_LENGTH)
#define RPMC_UPDATE_HMAC_KEY_MSG_LENGTH (RPMC_OP1_MSG_HEADER_LENGTH + RPMC_KEY_DATA_LENGTH + RPMC_SIGNATURE_LENGTH)
#define RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH (RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH + RPMC_SIGNATURE_LENGTH)
#define RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH (RPMC_OP1_MSG_HEADER_LENGTH + RPMC_TAG_LENGTH + RPMC_SIGNATURE_LENGTH)

// OP2 commands
#define RPMC_READ_DATA_MSG_LENGTH 2
#define RPMC_READ_DATA_ANSWER_LENGTH (1 + RPMC_TAG_LENGTH + RPMC_COUNTER_LENGTH + RPMC_SIGNATURE_LENGTH)


struct rpmc_status_register {
    uint8_t status;
    unsigned char tag[RPMC_TAG_LENGTH];
    uint32_t counter_data;
    unsigned char signature[RPMC_SIGNATURE_LENGTH];
};

static uint8_t get_extended_status(struct flashrom_flashctx * flash)
{
    const unsigned char extended_status_msg[RPMC_READ_DATA_MSG_LENGTH] = {
        flash->chip->rpmc_ctx.op2_opcode,
        0 // dummy
    };
    unsigned char status;

    if (spi_send_command(flash, RPMC_READ_DATA_MSG_LENGTH, 1, extended_status_msg, &status)) {
        msg_gerr("Reading extended status failed\n");
        status = ~0; // msb 1 implies all else should be 0, we use that as our failure state
    }

    return status;
}

static int get_extended_status_long(struct flashrom_flashctx * flash,
                                    struct rpmc_status_register * status,
                                    // optional to check values tag and signature against
                                    const unsigned char * const tag,
                                    const unsigned char * const key)
{
    const unsigned int tag_offset = 1;
    const unsigned int counter_data_offset = tag_offset + RPMC_TAG_LENGTH;
    const unsigned int signature_offset = counter_data_offset + RPMC_COUNTER_LENGTH;
    const unsigned char cmd[RPMC_READ_DATA_MSG_LENGTH] = {
        flash->chip->rpmc_ctx.op2_opcode,
        0 // dummy
    };
    unsigned char answer[RPMC_READ_DATA_ANSWER_LENGTH];

    int ret = spi_send_command(flash, RPMC_READ_DATA_MSG_LENGTH, RPMC_READ_DATA_ANSWER_LENGTH, cmd, answer) != 0;
    if (ret) {
        msg_gerr("reading extended status failed\n");
        return ret;
    }

    status->status = answer[0];

    memcpy(status->tag, answer + tag_offset, RPMC_TAG_LENGTH);

    status->counter_data = answer[counter_data_offset];
    status->counter_data = (status->counter_data << 8) | answer[counter_data_offset + 1];
    status->counter_data = (status->counter_data << 8) | answer[counter_data_offset + 2];
    status->counter_data = (status->counter_data << 8) | answer[counter_data_offset + 3];

    memcpy(status->signature, answer + signature_offset, RPMC_SIGNATURE_LENGTH);

    if (tag != NULL) {
        if (memcmp(tag, status->tag, RPMC_TAG_LENGTH) != 0) {
            msg_gwarn("Tag doesn't match counter might be false\n");
            ret = 1;
        }
    }

    if (key != NULL) {
        unsigned char * signature = HMAC(EVP_sha256(), key, RPMC_HMAC_KEY_LENGTH, answer + tag_offset, signature_offset - tag_offset, NULL, NULL);
        if (signature == NULL) {
            msg_gerr("Could not generate signature\n");
            ret = 1;
        } else if (memcmp(signature, status->signature, RPMC_SIGNATURE_LENGTH) != 0) {
            msg_gerr("Signature doesn't match\n");
            ret = 1;
        }
    }

    return ret;
}

static int poll_until_finished(struct flashrom_flashctx * flash)
{
    bool op_finished = false;

    while (!op_finished) {
        const unsigned char status_poll_msg = 0x05;
        unsigned char poll_response;

        // since we aren't really a time critical application we just sleep for the longest time
        if (usleep(flash->chip->rpmc_ctx.polling_long_delay_write_counter_us)) {
            msg_gdbg("%s: usleep failed\n", __func__);
        }

        switch (flash->chip->rpmc_ctx.busy_polling_method) {
            case POLL_READ_STATUS:
                if (spi_send_command(flash, 1, 1, &status_poll_msg, &poll_response)) {
                    msg_gerr("Polling Status-Register-1 failed\n");
                    return 1;
                }
                break;
            case POLL_OP2_EXTENDED_STATUS:
                poll_response = get_extended_status(flash);
                break;
            default:
                msg_gerr("Unsupported busy polling method found, this should not happen. Exiting...\n");
                return 1;
        }

        op_finished = (poll_response & 1) == 0;        
    }
    
    return 0;
}


static int calculate_hmac_key_register(const char * const keyfile, const uint32_t key_data, unsigned char * hmac_key_register)
{
    unsigned char key[RPMC_HMAC_KEY_LENGTH];
    unsigned char key_data_buf[RPMC_KEY_DATA_LENGTH];
    key_data_buf[0] = (key_data >> 24) & 0xff;
    key_data_buf[1] = (key_data >> 16) & 0xff;
    key_data_buf[2] = (key_data >> 8) & 0xff;
    key_data_buf[3] = key_data & 0xff;

    if (keyfile == NULL || read_buf_from_file(key, RPMC_HMAC_KEY_LENGTH, keyfile) != 0) {
        return 1;
    }

    unsigned char * key_ptr = HMAC(EVP_sha256(), key, RPMC_HMAC_KEY_LENGTH, key_data_buf, RPMC_KEY_DATA_LENGTH, hmac_key_register, NULL);
    if (key_ptr == NULL) {
        msg_gerr("Could not calculate HMAC signature for hmac storage\n");
        return 1;
    }
    
    return 0;
}

static int basic_checks(struct flashrom_flashctx * flash, const unsigned int counter_address)
{
    if ((flash->chip->feature_bits & FEATURE_FLASH_HARDENING) == 0) {
        msg_gerr("Flash hardening is not supported on this chip, aborting.\n");
        return 1;
    }

    if (counter_address >= flash->chip->rpmc_ctx.num_counters) {
        msg_gerr("Counter address is not in range, should be between 0 and %d.\n", flash->chip->rpmc_ctx.num_counters - 1);
        return 1;
    }

    return 0;
}

static int check_errors(const uint8_t status, const unsigned int command)
{
    
    if (status == 0x80) {
        return 0;
    }

    if (status & (1 << 4)) {
        msg_gerr("Previous counter value does not match.\n");
    } else if (status & (1 << 3)) {
        msg_gerr("Hmac key register is uninitialized.\n");
    } else if (status & (1 << 1)) {
        switch(command) {
            case 0x0:
                msg_gerr("Either Root Key Register Overwrite, Counter Address out of range or truncated signature mismatch.\n");
                break;
            case 0x1:
                msg_gerr("Counter is not initialized.\n");
                break;
        }
    } else if (status & (1 << 2)) {
        msg_gerr("Payload size incorrect, counter address out of range, commandtype out of range or signature mismatch.\n");
    }

    return 1;
}

static int send_and_wait(struct flashrom_flashctx * flash, const unsigned char * const msg, const size_t length)
{
    msg_gdbg("sending rpmc command\n");
    int ret = spi_send_command(flash, length, 0, msg, NULL);
    if (ret)
        return ret;

    // check operation status
    ret = poll_until_finished(flash);
    if (ret)
        return ret;
    
    msg_gdbg("done sending rpmc command\n");
    
    return 0;
}

static int sign_send_wait_check(struct flashrom_flashctx * flash,
                                unsigned char * const msg,
                                const size_t msg_length, 
                                const size_t signature_offset, 
                                const char * const keyfile, 
                                const uint32_t key_data) 
{
    unsigned char hmac_key_register[RPMC_HMAC_KEY_LENGTH];
    
    if (calculate_hmac_key_register(keyfile, key_data, hmac_key_register)) {
        return 1;
    }

    if (HMAC(EVP_sha256(), hmac_key_register, RPMC_HMAC_KEY_LENGTH, msg, signature_offset, msg + signature_offset, NULL) == NULL) {
        msg_gerr("Could not generate HMAC signature\n");
        return 1;
    }

    if (send_and_wait(flash, msg, msg_length)) {
        return 1;
    }

    if (check_errors(get_extended_status(flash), msg[1])){
        return 1;
    }
    
    return 0;
}

int rpmc_write_root_key(struct flashrom_flashctx * flash, const char * const keyfile, const unsigned int counter_address)
{
    const unsigned int key_offset = RPMC_OP1_MSG_HEADER_LENGTH;
    const unsigned int signature_offset = key_offset + RPMC_HMAC_KEY_LENGTH;
    const unsigned int signature_cutoff = RPMC_SIGNATURE_LENGTH - RPMC_TRUNCATED_SIG_LENGTH;

    unsigned char msg[RPMC_WRITE_ROOT_KEY_MSG_LENGTH];
    msg[0] = flash->chip->rpmc_ctx.op1_opcode; // Opcode
    msg[1] = 0x00; // CmdType
    msg[2] = counter_address; // CounterAddr
    msg[3] = 0; // Reserved

    if (basic_checks(flash, counter_address)) {
        return 1;
    }

    if (keyfile == NULL || read_buf_from_file(msg + key_offset, RPMC_HMAC_KEY_LENGTH, keyfile) != 0) {
        return 1;
    }

    unsigned char * signature = HMAC(EVP_sha256(), msg + key_offset, RPMC_HMAC_KEY_LENGTH, msg, RPMC_OP1_MSG_HEADER_LENGTH, NULL, NULL);
    if (signature == NULL) {
        msg_gerr("Could not calculate HMAC signature for message\n");
        return 1;
    }

    // need to truncate the signature a bit
    memcpy(msg + signature_offset, signature + signature_cutoff, RPMC_TRUNCATED_SIG_LENGTH);

    if (send_and_wait(flash, msg, RPMC_WRITE_ROOT_KEY_MSG_LENGTH)) {
        return 1;
    }

    if (check_errors(get_extended_status(flash), msg[1])){
        return 1;
    }

    msg_ginfo("Successfully wrote new root key for counter %u.\n", counter_address);
    return 0;
}

int rpmc_update_hmac_key(struct flashrom_flashctx * flash, const char * const keyfile, const uint32_t key_data, const unsigned int counter_address)
{
    const unsigned int signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_KEY_DATA_LENGTH;
    unsigned char msg[RPMC_UPDATE_HMAC_KEY_MSG_LENGTH];
    msg[0] = flash->chip->rpmc_ctx.op1_opcode; // Opcode
    msg[1] = 0x01; // CmdType
    msg[2] = counter_address; // CounterAddr
    msg[3] = 0; // Reserved
    msg[4] = (key_data >> 24) & 0xff;
    msg[5] = (key_data >> 16) & 0xff;
    msg[6] = (key_data >> 8) & 0xff;
    msg[7] = key_data & 0xff;
    
    if (basic_checks(flash, counter_address)) {
        return 1;
    }

    if (sign_send_wait_check(flash, msg, RPMC_UPDATE_HMAC_KEY_MSG_LENGTH, signature_offset, keyfile, key_data)) {
        return 1;
    }

    msg_ginfo("Successfully updated hmac key to 0x%08x for counter %u.\n", key_data, counter_address);
    return 0;
}

int rpmc_increment_counter(struct flashrom_flashctx * flash, const char * const keyfile, const uint32_t key_data, const unsigned int counter_address, const uint32_t previous_value)
{
    const unsigned int signature_offset = RPMC_OP1_MSG_HEADER_LENGTH + RPMC_COUNTER_LENGTH;
    unsigned char msg[RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH];
    msg[0] = flash->chip->rpmc_ctx.op1_opcode; // Opcode
    msg[1] = 0x02; // CmdType
    msg[2] = counter_address; // CounterAddr
    msg[3] = 0; // Reserved
    // CounterData
    msg[4] = (previous_value >> 24) & 0xff;
    msg[5] = (previous_value >> 16) & 0xff;
    msg[6] = (previous_value >> 8) & 0xff;
    msg[7] = previous_value & 0xff;

    if (basic_checks(flash, counter_address)) {
        return 1;
    }

    if (sign_send_wait_check(flash, msg, RPMC_INCREMENT_MONOTONIC_COUNTER_MSG_LENGTH, signature_offset, keyfile, key_data)) {
        return 1;
    }

    msg_ginfo("Successfully incremented counter %u.\n", counter_address);
    return 0;
}

int rpmc_get_monotonic_counter(struct flashrom_flashctx * flash, const char * const keyfile, const uint32_t key_data, const unsigned int counter_address)
{
    unsigned char hmac_key_register[RPMC_HMAC_KEY_LENGTH];
    const unsigned int tag_offset = RPMC_OP1_MSG_HEADER_LENGTH;
    const unsigned int signature_offset = tag_offset + RPMC_TAG_LENGTH;
    unsigned char msg[RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH];
    msg[0] = flash->chip->rpmc_ctx.op1_opcode; // Opcode
    msg[1] = 0x03; // CmdType
    msg[2] = counter_address; // CounterAddr
    msg[3] = 0; // Reserved

    if (basic_checks(flash, counter_address)) {
        return 1;
    }

    if (RAND_bytes(msg + tag_offset, RPMC_TAG_LENGTH) != 1) {
        msg_gerr("Could not generate random tag.\n");
        return 1;
    }

    msg_gdbg("Random tag is:");
    for (size_t i = 0; i < RPMC_TAG_LENGTH; i++) {
        msg_gdbg(" 0x%02x", msg[tag_offset + i]);
    }
    msg_gdbg("\n");

    if (calculate_hmac_key_register(keyfile, key_data, hmac_key_register)) {
        return 1;
    }

    if (HMAC(EVP_sha256(), hmac_key_register, RPMC_HMAC_KEY_LENGTH, msg, signature_offset, msg + signature_offset, NULL) == NULL) {
        msg_gerr("Could not generate HMAC signature\n");
        return 1;
    }

    if (send_and_wait(flash, msg, RPMC_GET_MONOTONIC_COUNTER_MSG_LENGTH)) {
        return 1;
    }

    struct rpmc_status_register status;    
    if (get_extended_status_long(flash, &status, msg + tag_offset, hmac_key_register)) {
        return 1;
    }
    
    if (check_errors(status.status, msg[1])) {
        return 1;
    }

    msg_ginfo("Returned counter value %u for counter %u\n", status.counter_data, counter_address);
    return 0;
}

int rpmc_read_data(struct flashrom_flashctx * flash)
{
    // hack around not having a counter address
    if (basic_checks(flash, 0)) {
        return 1;
    }

    struct rpmc_status_register status;

    if (get_extended_status_long(flash, &status, NULL, NULL)) {
        return 1;
    }

    msg_ginfo("Reading rpmc data returned:\n");
   
    // pretty print status
    char bin_buffer[9];
    uint8_t status_bits = status.status;
    for (int i = 7; i >= 0; i--){
        bin_buffer[i] = '0' + (status_bits & 1);
        status_bits = status_bits >> 1;
    }
    bin_buffer[8] = '\0';
    msg_ginfo("Extended Status: 0b%s\n", bin_buffer);

    msg_ginfo("Tag:\n");
    for (size_t i = 0; i < RPMC_TAG_LENGTH; i++){
        msg_ginfo("0x%02x ", status.tag[i]);
    }
    msg_ginfo("\n");

    msg_ginfo("Counter: %u\n", status.counter_data);

    msg_ginfo("Signature:\n");
    for (size_t i = 0; i < RPMC_SIGNATURE_LENGTH; i++){
        msg_ginfo("0x%02x ", status.signature[i]);
    }
    msg_ginfo("\n");

    return 0;
}
