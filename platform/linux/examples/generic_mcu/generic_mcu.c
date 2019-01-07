/**
 * Copyright 2018 Afero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "af_lib.h"
#include "af_logger.h"
#include "af_module_states.h"
#include "af_module_commands.h"
#include "system_attributes.h"
#include "af_mcu_ota.h"
#include "af_utils.h"
#include "sha2.h"
#include "linux_uart.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <af_mcu_ota.h>

#define ATTR_PRINT_HEADER_LEN     60
#define ATTR_PRINT_MAX_VALUE_LEN  512   // Each byte is 2 ASCII characters in HEX.
#define ATTR_PRINT_BUFFER_LEN     (ATTR_PRINT_HEADER_LEN + ATTR_PRINT_MAX_VALUE_LEN)

char attr_print_buffer[ATTR_PRINT_BUFFER_LEN];
af_lib_t* sAf_lib = NULL;

typedef struct {
    af_ota_begin_info_t begin_info;
    af_ota_apply_info_t apply_info;
    char filename[64];
    FILE *file;
    uint32_t received_so_far;
    long transfer_start_time;
    long chunk_start_time;
} ota_state_t;

#define OTA_FILE_NAME_PREFIX    "ota_file_type"
static ota_state_t ota_state;


#define POLL_TIMEOUT                (10)
#define MAX_BUF                     256

static void getPrintAttrHeader(const char *sourceLabel, const char *attrLabel, const uint16_t attribute_id, const uint16_t value_len) {
    memset(attr_print_buffer, 0, ATTR_PRINT_BUFFER_LEN);
    snprintf(attr_print_buffer, ATTR_PRINT_BUFFER_LEN, "%s id: %s len: %05d value: ", sourceLabel, attrLabel, value_len);
}

static void printAttrBool(const char *sourceLabel, const char *attrLabel, const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value) {
    getPrintAttrHeader(sourceLabel, attrLabel, attribute_id, value_len);
    if (value_len > 0) {
        strcat(attr_print_buffer, *value == 1 ? "true" : "false");
    }
    af_logger_println_buffer(attr_print_buffer);
}

static void printAttr8(const char *sourceLabel, const char *attrLabel, const uint8_t attribute_id, const uint16_t value_len, const uint8_t *value) {
    getPrintAttrHeader(sourceLabel, attrLabel, attribute_id, value_len);
    if (value_len > 0) {
        char intStr[6];
        snprintf(intStr, sizeof(intStr), "%d", *((int8_t *)value));
        strcat(attr_print_buffer, intStr);
    }
    af_logger_println_buffer(attr_print_buffer);
}

static void printAttr16(const char *sourceLabel, const char *attrLabel, const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value) {
    getPrintAttrHeader(sourceLabel, attrLabel, attribute_id, value_len);
    if (value_len > 0) {
        char intStr[6];
        snprintf(intStr, sizeof(intStr), "%d", *((int16_t *)value));
        strcat(attr_print_buffer, intStr);
    }
    af_logger_println_buffer(attr_print_buffer);
}

static void printAttr32(const char *sourceLabel, const char *attrLabel, const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value) {
    getPrintAttrHeader(sourceLabel, attrLabel, attribute_id, value_len);
    if (value_len > 0) {
        char intStr[11];
        snprintf(intStr, sizeof(intStr), "%d", *((int32_t *)value));
        strcat(attr_print_buffer, intStr);
    }
    af_logger_println_buffer(attr_print_buffer);
}

static void printAttrHex(const char *sourceLabel, const char *attrLabel, const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value) {
    getPrintAttrHeader(sourceLabel, attrLabel, attribute_id, value_len);
    for (int i = 0; i < value_len && i < ATTR_PRINT_MAX_VALUE_LEN; i++) {
        char hexStr[4];
        snprintf(hexStr, sizeof(hexStr), "%02X", value[i]);
        strcat(attr_print_buffer, hexStr);
    }
    af_logger_println_buffer(attr_print_buffer);
}

static void printAttrStr(const char *sourceLabel, const char *attrLabel, const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value) {
    getPrintAttrHeader(sourceLabel, attrLabel, attribute_id, value_len);
    int len = strlen(attr_print_buffer);
    for (int i = 0; i < value_len; i++) {
        attr_print_buffer[len + i] = (char)value[i];
    }
    af_logger_println_buffer(attr_print_buffer);
}

static void printAttribute(const char *label, const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value, const af_lib_error_t error) {
    if (error != AF_SUCCESS) {
        af_logger_print_buffer("***** ERROR: ");
        af_logger_print_value(error);
        af_logger_print_buffer(": ");
    }
    switch (attribute_id) {
        case AF_BOOTLOADER_VERSION:
            printAttrHex(label, "AF_BOOTLOADER_VERSION", attribute_id, value_len, value);
            break;

        case AF_SOFTDEVICE_VERSION:
            printAttrHex(label, "AF_SOFTDEVICE_VERSION", attribute_id, value_len, value);
            break;

        case AF_APPLICATION_VERSION:
            printAttrHex(label, "AF_APPLICATION_VERSION", attribute_id, value_len, value);
            break;

        case AF_PROFILE_VERSION:
            printAttrHex(label, "AF_PROFILE_VERSION", attribute_id, value_len, value);
            break;

        case AF_SYSTEM_ASR_STATE:
            printAttr8(label, "AF_SYSTEM_ASR_STATE", attribute_id, value_len, value);
            break;

        case AF_SYSTEM_LOW_POWER_WARN:
            printAttr8(label, "AF_ATTRIBUTE_LOW_POWER_WARN", attribute_id, value_len, value);
            break;

        case AF_SYSTEM_REBOOT_REASON:
            printAttrStr(label, "AF_REBOOT_REASON", attribute_id, value_len, value);
            break;

        case AF_SYSTEM_MCU_INTERFACE:
            printAttr8(label, "AF_SYSTEM_MCU_INTERFACE", attribute_id, value_len, value);
            break;

        case AF_SYSTEM_LINKED_TIMESTAMP:
            printAttr32(label, "AF_SYSTEM_LINKED_TIMESTAMP", attribute_id, value_len, value);
            break;

        case AF_UTC_TIME:
            printAttr32(label, "AF_UTC_TIME", attribute_id, value_len, value);
            break;

        case AF_DEVICE_ID:
            printAttrHex(label, "AF_DEVICE_ID", attribute_id, value_len, value);
            break;

        case AF_ASSOCIATION_ID:
            printAttrHex(label, "AF_ASSOCIATION_ID", attribute_id, value_len, value);
            break;

        case AF_COMPANY_CODE:
            printAttrHex(label, "AF_COMPANY_CODE", attribute_id, value_len, value);
            break;

        case AF_ONLINE_STATUS:
            printAttrHex(label, "AF_ONLINE_STATUS", attribute_id, value_len, value);
            break;

        default:{
            char attrLabel[64];
            snprintf(attrLabel, sizeof(attrLabel), "%u", attribute_id);
            printAttrHex(label, attrLabel, attribute_id, value_len, value);
        }
            break;
    }
}

static void handle_ota_info(const uint16_t value_len, const uint8_t *value) {
    af_ota_info_t *ota_info = (af_ota_info_t*)value;
    switch (ota_info->state) {
        case AF_OTA_IDLE:
            fprintf(stdout, "handle_ota_info: AF_OTA_IDLE\n");
            break;
        case AF_OTA_TRANSFER_BEGIN:
        {
            memset(&ota_state, 0, sizeof(ota_state));
            ota_state.begin_info.ota_type = af_utils_read_little_endian_16((const uint8_t*)&ota_info->info.begin_info.ota_type);
            ota_state.begin_info.size = af_utils_read_little_endian_32((const uint8_t*)&ota_info->info.begin_info.size);
            fprintf(stdout, "handle_ota_info: about to get an MCU OTA for type %u and size %u\n", ota_state.begin_info.ota_type, ota_state.begin_info.size);
            // Open the file to save the data we're about to get
            snprintf(ota_state.filename, sizeof(ota_state.filename), "%s.%d", OTA_FILE_NAME_PREFIX, ota_state.begin_info.ota_type);
            ota_state.file = fopen(ota_state.filename, "wb");
            if (ota_state.file != NULL) {
                fprintf(stdout, "handle_ota_info: opened file %s to store MCU OTA\n", ota_state.filename);
            } else {
                fprintf(stderr, "handle_ota_info: error opening file %s to store MCU OTA: %d:%s\n", ota_state.filename, errno, strerror(errno));
                // Hmmm, couldn't open the file we wanted to save the data to.  To stop the ASR from sending us any data we'll set the state to AF_OTA_IDLE.
                ota_info->state = AF_OTA_IDLE;
            }
            ota_state.transfer_start_time = af_utils_millis();
            ota_state.chunk_start_time = af_utils_millis();
            // Respond back with an UPDATE to this attribute id so the ASR will start sending us the actual data
            int res = af_lib_set_attribute_bytes(sAf_lib, AF_MCU_OTA_INFO, value_len, value);
            if (res != AF_SUCCESS) {
                fprintf(stderr, "handle_ota_info: error setting attribute %u, %d\n", AF_MCU_OTA_INFO, res);
            }
        }
            break;
        case AF_OTA_TRANSFER_END:
            fprintf(stdout, "handle_ota_info: AF_OTA_TRANSFER_END\n");
            break;
        case AF_OTA_APPLY:
            fprintf(stdout, "handle_ota_info: AF_OTA_APPLY\n");
            // We're supposed to "apply" the image here, but since it's just a file we'll just squirrel away the version number so we have it
            memcpy(&ota_state.apply_info, &ota_info->info.verify_info, sizeof(ota_state.apply_info));
            // Now we're supposed to set the state to AF_OTA_IDLE to let the ASR know we're done
            ota_info->state = AF_OTA_IDLE;
            int res = af_lib_set_attribute_bytes(sAf_lib, AF_MCU_OTA_INFO, value_len, value);
            if (res != AF_SUCCESS) {
                fprintf(stderr, "handle_ota_info: error setting attribute %u, %d\n", AF_MCU_OTA_INFO, res);
            }
            fprintf(stdout, "handle_ota_info: OTA type %u of size %u has version %llu\n", ota_state.begin_info.ota_type, ota_state.begin_info.size, ota_state.apply_info.version_id);
            // Since this is just a file our MCU OTA will always "work" so now all we have to do is report the new version number for our type
            res = af_lib_set_attribute_64(sAf_lib, AF_MCU_TYPE_TO_VERSION_ATTRIBUTE(ota_state.begin_info.ota_type), ota_state.apply_info.version_id);
            if (res != AF_SUCCESS) {
                fprintf(stderr, "handle_ota_info: error setting attribute %u, %d\n", AF_MCU_TYPE_TO_VERSION_ATTRIBUTE(ota_state.begin_info.ota_type), res);
            }
            break;
        case AF_OTA_FAIL:
            fprintf(stdout, "handle_ota_info: AF_OTA_FAIL\n");
            // The sha256 didn't verify, we should just delete the file we just got...
            fprintf(stdout, "handle_ota_info: OTA verify failed, deleting file %s\n", ota_state.filename);
            unlink(ota_state.filename);
            break;
        default:
            fprintf(stdout, "handle_ota_info: unhandled state %d\n", ota_info->state);
            break;
    }
}

static void handle_ota_transfer(const uint16_t value_len, const uint8_t *value) {
    // The format of this attribute is the first 4 bytes are the offset of the data and the rest are the actual data.
    // The update to this attribute should just contain the next offset you want the data from (or AF_MCU_OTA_STOP_TRANSFER_OFFSET to stop the transfer
    uint32_t offset = af_utils_read_little_endian_32(value);
    bool done = false;
    if (offset != ota_state.received_so_far) {
        // Hmmm, this is strange we're getting data for an offset that we don't expect, respond with the correct value
        fprintf(stdout, "handle_ota_transfer: got offset %u but was expecting %u\n", offset, ota_state.received_so_far);
    } else {
        if (ota_state.file != NULL) {
            uint32_t amount_to_write = value_len - sizeof(offset);
            uint32_t written = fwrite(value + sizeof(offset), 1, amount_to_write, ota_state.file);
            if (written != amount_to_write) {
                fprintf(stdout, "handle_ota_transfer: unable to write all data, written %u, expected %u\n", written, amount_to_write);
            }
            ota_state.received_so_far += written;
            long now = af_utils_millis();
            float chunk_speed = ((float)amount_to_write/(now - ota_state.chunk_start_time))*1000;

            fprintf(stdout, "handle_ota_transfer: received_so_far %u, total %u, speed %f bytes/second\n", ota_state.received_so_far, ota_state.begin_info.size, chunk_speed);

            // Stop if we've gotten it all (although it should never really be bigger than the size!)
            if (ota_state.received_so_far >= ota_state.begin_info.size) {
                float total_speed = ((float)ota_state.begin_info.size/(now - ota_state.transfer_start_time))*1000;
                fprintf(stdout, "handle_ota_transfer: finished, received %u bytes of expected %u bytes, transfer speed %f bytes/second\n", ota_state.received_so_far, ota_state.begin_info.size, total_speed);
                fclose(ota_state.file);
                ota_state.file = NULL;
                ota_state.received_so_far = AF_MCU_OTA_STOP_TRANSFER_OFFSET;
                done = true;
            }
        } else {
            // If the file is NULL (which it should never really be) then tell the ASR to stop sending us data since we obviously can't deal with it in our current state
            ota_state.received_so_far = AF_MCU_OTA_STOP_TRANSFER_OFFSET;
        }
    }

    ota_state.chunk_start_time = af_utils_millis();
    uint8_t result[sizeof(uint32_t)];
    af_utils_write_little_endian_32(ota_state.received_so_far, result);
    int res = af_lib_set_attribute_bytes(sAf_lib, AF_MCU_OTA_TRANSFER, sizeof(result), result);
    if (res != AF_SUCCESS) {
        fprintf(stderr, "handle_ota_transfer: error setting attribute %u, %d\n", AF_MCU_OTA_TRANSFER, res);
    }

    // If we're done because we got all the bits we were expecting then sha what we saved and send it to the ASR to verify
    if (done) {
        isc_sha256_t sha256;
        af_ota_info_t ota_info;
        static const int bufSize = 1024;
        uint8_t buffer[bufSize];
        int bytesRead = 0;
        uint8_t sha[32];
        FILE *file = fopen(ota_state.filename, "rb");
        if (!file) {
            fprintf(stderr, "handle_ota_transfer: unable to open file %s, %d: %s\n", ota_state.filename, errno, strerror(errno));
            return; // Not much we can do here, although should never happen...
        }

        isc_sha256_init(&sha256);

        fprintf(stdout, "handle_ota_transfer: generating sha for file %s...\n", ota_state.filename);
        uint32_t imageSize = 0;
        while((bytesRead = fread(buffer, 1, bufSize, file))) {
            isc_sha256_update(&sha256, buffer, bytesRead);
            imageSize += bytesRead;
        }
        isc_sha256_final(sha, &sha256);
        memcpy(ota_info.info.verify_info.sha, sha, sizeof(ota_info.info.verify_info.sha));
        fclose(file);

        fprintf(stdout, "handle_ota_transfer: generated sha for file %s, image size %u\n", ota_state.filename, imageSize);

        ota_info.state = AF_OTA_VERIFY_SIGNATURE;
        res = af_lib_set_attribute_bytes(sAf_lib, AF_MCU_OTA_INFO, sizeof(ota_info), (uint8_t*)&ota_info);
        if (res != AF_SUCCESS) {
            fprintf(stderr, "handle_ota_transfer: error setting attribute %u, %d\n", AF_MCU_OTA_INFO, res);
        }
    }
}

void attr_notify_handler_event(const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value, const af_lib_error_t error)
{
    // Don't dump the contents of the AF_MCU_OTA_INFO or AF_MCU_OTA_TRANSFER attribute
    if (attribute_id != AF_MCU_OTA_INFO && attribute_id != AF_MCU_OTA_TRANSFER) {
        printAttribute("AF_LIB_EVENT_ASR_NOTIFICATION", attribute_id, value_len, value, error);
    } else {
        char attrLabel[64];
        snprintf(attrLabel, sizeof(attrLabel), "%u", attribute_id);
        getPrintAttrHeader("AF_LIB_EVENT_ASR_NOTIFICATION", attrLabel, attribute_id, value_len);
        af_logger_println_buffer(attr_print_buffer);
    }

    switch (attribute_id) {
        case AF_SYSTEM_ASR_STATE:
            af_logger_print_buffer("ASR state: ");
            switch (value[0]) {
                case AF_MODULE_STATE_REBOOTED:
                    af_logger_println_buffer("Rebooted");
                    break;

                case AF_MODULE_STATE_LINKED:
                    af_logger_println_buffer("Linked");
                    break;

                case AF_MODULE_STATE_UPDATING:
                    af_logger_println_buffer("Updating");
                    break;

                case AF_MODULE_STATE_UPDATE_READY:
                    af_logger_println_buffer("Update ready - rebooting");
                    while (af_lib_set_attribute_32(sAf_lib, AF_SYSTEM_COMMAND, AF_MODULE_COMMAND_REBOOT) != AF_SUCCESS) {
                        af_lib_loop(sAf_lib);
                    }
                    break;

                case AF_MODULE_STATE_INITIALIZED:
                    af_logger_println_buffer("Initialized");
                    break;

                case AF_MODULE_STATE_RELINKED:
                    af_logger_println_buffer("Relinked");
                    break;

                default:
                    af_logger_println_value(value[0]);
                    break;
            }
            break;
        case AF_ONLINE_STATUS:
            af_logger_print_buffer("Online state: ");
            if (value[0]) {
                af_logger_print_buffer("Online, ");
                if (AF_INTERFACE_BLE == value[1]) {
                    af_logger_println_buffer("BLE");
                } else if (AF_INTERFACE_WIFI == value[1]) {
                    af_logger_print_buffer("Wifi, Bars: ");
                    af_logger_println_value(value[2]);
                } else {
                    af_logger_println_buffer("Unknown!");
                }
            } else {
                af_logger_println_buffer("Offline");
            }
            break;
        case AF_MCU_OTA_INFO:
            handle_ota_info(value_len, value);
            break;
        case AF_MCU_OTA_TRANSFER:
            handle_ota_transfer(value_len, value);
            break;
        default:
            break;
    }
}

static void get_response_handler_event(const af_lib_error_t error, const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value) {
    printAttribute("AF_LIB_EVENT_ASR_GET_RESPONSE", attribute_id, value_len, value, error);

    // If the attribute id is AF_ATTRIBUTE_ID_ASR_CAPABILITIES then we can safely query afLib to see what the ASR supports
    if (AF_ATTRIBUTE_ID_ASR_CAPABILITIES == attribute_id) {
        // Let's see what the ASR supports
        int result = af_lib_asr_has_capability(sAf_lib, AF_ASR_CAPABILITY_MCU_OTA);
        fprintf(stdout, "attrGetResponseHandler: ASR capability AF_ASR_CAPABILITY_MCU_OTA, supported %u\n", AF_SUCCESS == result);
    }
}

void attr_event_callback(const af_lib_event_type_t event_type, const af_lib_error_t error, const uint16_t attribute_id, const uint16_t value_len, const uint8_t *value) {
    switch (event_type) {
        case AF_LIB_EVENT_ASR_SET_RESPONSE:         // Response to af_lib_set_attribute() for an ASR attribute
            printAttribute("AF_LIB_EVENT_ASR_SET_RESPONSE", attribute_id, value_len, value, error);
            break;
        case AF_LIB_EVENT_MCU_SET_REQ_SENT:         // Request from af_lib_set_attribute() for an MCU attribute has been sent to ASR
            printAttribute("AF_LIB_EVENT_MCU_SET_REQ_SENT", attribute_id, value_len, value, error);
            break;
        case AF_LIB_EVENT_MCU_SET_REQ_REJECTION:    // Request from af_lib_set_attribute() for an MCU attribute was rejected by ASR
            printAttribute("AF_LIB_EVENT_MCU_SET_REQ_REJECTION", attribute_id, value_len, value, error);
            break;
        case AF_LIB_EVENT_ASR_GET_RESPONSE:         // Response to af_lib_get_attribute()
            get_response_handler_event(error, attribute_id, value_len, value);
            break;
        case AF_LIB_EVENT_MCU_DEFAULT_NOTIFICATION: // Unsolicited default notification for an MCU attribute
            printAttribute("AF_LIB_EVENT_MCU_DEFAULT_NOTIFICATION", attribute_id, value_len, value, error);
            break;
        case AF_LIB_EVENT_ASR_NOTIFICATION:         // Unsolicited notification of non-MCU attribute change
            attr_notify_handler_event(attribute_id, value_len, value, error);
            break;
        case AF_LIB_EVENT_MCU_SET_REQUEST:          // Request from ASR to MCU to set an MCU attribute, requires a call to af_lib_send_set_response()
            printAttribute("AF_LIB_EVENT_MCU_SET_REQUEST", attribute_id, value_len, value, error);
            af_lib_error_t result = af_lib_send_set_response(sAf_lib, attribute_id, true, value_len, value);
            if (result != AF_SUCCESS) {
                fprintf(stderr, "attr_event_callback: error %d from af_lib_send_set_response for attribute %u\n", result, attribute_id);
            }
            break;
        case AF_LIB_EVENT_COMMUNICATION_BREAKDOWN:
            fprintf(stdout, "AF_LIB_EVENT_COMMUNICATION_BREAKDOWN!!!\n");
            break;
        default:
            printAttribute("unhandledEvent", attribute_id, value_len, value, error);
            break;
    }
}

static uint8_t hex_to_val(const char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    else if (ch >= 'a' && ch <= 'f')
        return 10 + ch - 'a';
    else if (ch >= 'A' && ch <= 'F')
        return 10 + ch - 'A';
    else
        return -1;
}

void hex_2_bytes(char *hex_str, uint8_t *bytes) {
    for (uint8_t i = 0; i < strlen((char *)hex_str); i+=2) {
        bytes[i / 2] = (hex_to_val(hex_str[i]) << 4) | hex_to_val(hex_str[i + 1]);
    }
}

static void command_usage() {
    fprintf(stdout, "************************************************************************\n");
    fprintf(stdout, "Available commands:\n");
    fprintf(stdout, "\tget <attribute id>\n");
    fprintf(stdout, "\tset <attribute id> <attribute type> <value in hex>\n");
    fprintf(stdout, "\t\tattribute types are: \n");
    fprintf(stdout, "\t\t\tATTRIBUTE_TYPE_BOOLEAN = %u\n", ATTRIBUTE_TYPE_BOOLEAN);
    fprintf(stdout, "\t\t\tATTRIBUTE_TYPE_SINT8 = %u\n", ATTRIBUTE_TYPE_SINT8);
    fprintf(stdout, "\t\t\tATTRIBUTE_TYPE_SINT16 = %u\n", ATTRIBUTE_TYPE_SINT16);
    fprintf(stdout, "\t\t\tATTRIBUTE_TYPE_SINT32 = %u\n", ATTRIBUTE_TYPE_SINT32);
    fprintf(stdout, "\t\t\tATTRIBUTE_TYPE_SINT64 = %u\n", ATTRIBUTE_TYPE_SINT64);
    fprintf(stdout, "\t\t\tATTRIBUTE_TYPE_FIXED_16_16 = %u\n", ATTRIBUTE_TYPE_FIXED_16_16);
    fprintf(stdout, "\t\t\tATTRIBUTE_TYPE_UTF8S = %u\n", ATTRIBUTE_TYPE_UTF8S);
    fprintf(stdout, "\t\t\tATTRIBUTE_TYPE_BYTES = %u\n", ATTRIBUTE_TYPE_BYTES);
    fprintf(stdout, "************************************************************************\n");
}

static void handle_command(char* buffer) {
    // Replace the \n character with a \0
    int str_len = strlen(buffer);
    buffer[str_len-1] = '\0';

    if (1 == str_len) {
        return command_usage();
    }

    char *token = strsep(&buffer, " ");

    if (strncmp(token, "get", 3) == 0) {
        // Get the attribute id from the buffer
        token = strsep(&buffer, " ");
        if (!token || !strlen(token)) {
            return command_usage();
        }
        uint16_t attribute_id = atoi(token);
        if (0 == attribute_id) {
            return command_usage();
        }
        int res = af_lib_get_attribute(sAf_lib, attribute_id);
        if (res != AF_SUCCESS) {
            fprintf(stderr, "Error getting attribute %u, %d\n", attribute_id, res);
        } else {
            fprintf(stdout, "Getting attribute %u\n", attribute_id);
        }
    } else if (strncmp(token, "set", 3) == 0) {
        token = strsep(&buffer, " ");
        if (!token || !strlen(token)) {
            return command_usage();
        }
        uint16_t attribute_id = atoi(token);
        if (0 == attribute_id) {
            return command_usage();
        }

        token = strsep(&buffer, " ");
        if (!token || !strlen(token)) {
            return command_usage();
        }
        uint8_t attribute_type = atoi(token);

        token = strsep(&buffer, " ");
        if (!token || !strlen(token)) {
            return command_usage();
        }

        uint64_t attribute_value = 0;
        uint16_t attribute_len = 0;
        uint8_t binary_attr_value[MAX_BUF];

        switch (attribute_type) {
            case ATTRIBUTE_TYPE_BOOLEAN:
            case ATTRIBUTE_TYPE_SINT8:
            case ATTRIBUTE_TYPE_SINT16:
            case ATTRIBUTE_TYPE_SINT32:
                attribute_value = atoi(token);
                break;
            case ATTRIBUTE_TYPE_SINT64:
                attribute_value = strtoll(token, NULL, 10);
                break;
            case ATTRIBUTE_TYPE_FIXED_16_16:
                // TODO, fix me...
                break;
            case ATTRIBUTE_TYPE_UTF8S:
            case ATTRIBUTE_TYPE_BYTES:
                attribute_len = strlen(token)/2;
                hex_2_bytes(token, binary_attr_value);
                break;
            default:
                return command_usage();
        }

        int res = AF_SUCCESS;
        switch (attribute_type) {
            case ATTRIBUTE_TYPE_BOOLEAN:
                res = af_lib_set_attribute_bool(sAf_lib, attribute_id, attribute_value);
                break;
            case ATTRIBUTE_TYPE_SINT8:
                res = af_lib_set_attribute_8(sAf_lib, attribute_id, attribute_value);
                break;
            case ATTRIBUTE_TYPE_SINT16:
                res = af_lib_set_attribute_16(sAf_lib, attribute_id, attribute_value);
                break;
            case ATTRIBUTE_TYPE_SINT32:
                res = af_lib_set_attribute_32(sAf_lib, attribute_id, attribute_value);
                break;
            case ATTRIBUTE_TYPE_SINT64:
                res = af_lib_set_attribute_64(sAf_lib, attribute_id, attribute_value);
                break;
            case ATTRIBUTE_TYPE_FIXED_16_16:
                // TODO, fix me...
                break;
            case ATTRIBUTE_TYPE_UTF8S:
                res = af_lib_set_attribute_str(sAf_lib, attribute_id, attribute_len, (char*)binary_attr_value);
                break;
            case ATTRIBUTE_TYPE_BYTES:
                res = af_lib_set_attribute_bytes(sAf_lib, attribute_id, attribute_len, binary_attr_value);
                break;
            default:
                fprintf(stderr, "Unhandled attribute type %d\n", attribute_type);
        }

        if (res != AF_SUCCESS) {
            fprintf(stderr, "Error setting attribute %u, %d\n", attribute_id, res);
        } else {
            fprintf(stdout, "Setting attribute %u\n", attribute_id);
        }
    } else {
        command_usage();
    }
}

static int usage()
{
    fprintf(stdout, "generic_mcu -b [uartBaudRate] -D [uartDevicePath]\n");
    return -1;
}

int main(int argc, char *argv[])
{
    struct pollfd fdset[1];
    int nfds = 1;
    int timeout, rc;
    char buf[MAX_BUF];
    int len;

    char *uart_baud_rate = NULL, *uart_device_path = NULL;

    for (int i = 1; i < argc; i++) {
        const char* s = argv[i];
        if (s[0] == '-')
        {
            switch(s[1]) {
                case 'b':
                    if (i == argc-1) {
                        return usage();
                    }
                    uart_baud_rate = argv[++i];
                    break;
                case 'D':
                    if (i == argc-1) {
                        return usage();
                    }
                    uart_device_path = argv[++i];
                    break;
                default:
                    return usage();
            }
        } else
            usage();
    }

    if (!uart_baud_rate && !uart_device_path) {
        return usage();
    }

    fprintf(stdout, "generic_mcu using uart path %s and baud rate %s\n", uart_device_path, uart_baud_rate);

    uint32_t baud_rate = atoi(uart_baud_rate);

    af_transport_t *linux_uart = linux_uart_create(uart_device_path, baud_rate);

    sAf_lib = af_lib_create_with_unified_callback(attr_event_callback, linux_uart);

    struct timespec sleep_time;
    struct timespec remaining;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = 250000;
    nanosleep(&sleep_time, &remaining);

    while (1) {
        fdset[0].fd = STDIN_FILENO;
        fdset[0].events = POLLIN;

        rc = poll(fdset, nfds, POLL_TIMEOUT);

        if (rc < 0) {
            printf("\npoll() failed!\n");
            return -1;
        }

        if (fdset[0].revents & POLLIN) {
            memset(buf, 0, MAX_BUF);
            read(fdset[0].fd, buf, MAX_BUF);
            handle_command(buf);
            //printf("\npoll() stdin read 0x%2.2X\n", (unsigned int) buf[0]);
        }

        af_lib_loop(sAf_lib);
        fflush(stdout);
    }

    return 0;
}

