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

#include <stdio.h>
#include "af_logger.h"

void af_logger_print_value(int32_t val) {
    fprintf(stdout, "%d", val);
}

void af_logger_print_buffer(const char* val) {
    fprintf(stdout, "%s", val);
}

void af_logger_print_formatted_value(int32_t val, af_logger_format_t format) {
    const char* format_str = NULL;
    switch (format) {
        case AF_LOGGER_BIN:
            format_str = NULL;
            break;
        case AF_LOGGER_OCT:
            format_str = "%o";
            break;
        case AF_LOGGER_DEC:
            format_str = "%d";
            break;
        case AF_LOGGER_HEX:
            format_str = "0x%X";
            break;
    }

    if (format_str != NULL) {
        fprintf(stdout, format_str, val);
    } else {
        // Must be binary
        int i = 8 * sizeof(val);
        while (i--) {
            putchar('0' + ((val >> i) & 1));
        }
    }
}

void af_logger_println_value(int32_t val) {
    fprintf(stdout, "%d\n", val);
}

void af_logger_println_buffer(const char* val) {
    fprintf(stdout, "%s\n", val);
}

void af_logger_println_formatted_value(int32_t val, af_logger_format_t format) {
    const char* format_str = NULL;
    switch (format) {
        case AF_LOGGER_BIN:
            format_str = NULL;
            break;
        case AF_LOGGER_OCT:
            format_str = "%o\n";
            break;
        case AF_LOGGER_DEC:
            format_str = "%d\n";
            break;
        case AF_LOGGER_HEX:
            format_str = "0x%02X\n";
            break;
    }

    if (format_str != NULL) {
        fprintf(stdout, format_str, val);
    } else {
        // Must be binary
        int i = 8 * sizeof(val);
        while (i--) {
            putchar('0' + ((val >> i) & 1));
        }
        fprintf(stdout, "\n");
    }
}
