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

#include "linux_uart.h"
#include "af_lib.h"
#include "af_logger.h"
#include "af_msg_types.h"
#include "af_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>			//Used for UART
#include <fcntl.h>			//Used for UART
#include <termios.h>		//Used for UART
#include <sys/socket.h>
#include <stdbool.h>

#define INT_CHAR                            0x32

#define DEBUG_UART                          0

struct af_transport_t {
    int socket;
    uint8_t c;
    bool have_cached_data;
};

static int linux_uart_send(af_transport_t *af_transport, const uint8_t* dataToSend, uint32_t dataToSendLength) {
    uint32_t n = 0;
    while (n < dataToSendLength) {
        int count = write(af_transport->socket, dataToSend+n, 1); // Do single byte writes so we don't overwhelm the UART interface
        if (count < 0) {
            int lastErrorNo = errno;
            fprintf(stderr, "linux_uart_send(%d): error sending data %d:%s\n", af_transport->socket, lastErrorNo, strerror(lastErrorNo));
            if (EPIPE == lastErrorNo) {
                // Crap, the socket isn't connected anymore, let's try and fix that by re-connecting if we're not closed
                /*if (!mClosed) {
                    Open();
                }*/
            } else if (EWOULDBLOCK == lastErrorNo || EAGAIN == lastErrorNo) {
                // TODO, since this is a non-blocking socket we'll need to handle the non-error case of getting back an EWOULDBLOCK from the send.
                // For now just log to see how often it happens
                fprintf(stdout, "linux_uart_send(%d): got a would block for data length %u\n", af_transport->socket, dataToSendLength);
            }
            return count;
        } else if (count == 0) {
            return 0;
        } else {
            n += count;
        }
    }

#if DEBUG_UART
    fprintf(stdout, "linux_uart_send(): size %d\ndata: ", dataToSendLength);

    for (int i = 0; i < dataToSendLength; i++) {
        fprintf(stdout, "0x%X ", dataToSend[i]);
    }
    fprintf(stdout, "\n total send %d\n", n);
#endif

    return n;
}

static int linux_uart_read(af_transport_t *af_transport, uint8_t* buffer, uint32_t size) {
    // First a sanity check to make sure we can actually do something
    if (0 == size) {
        // We can't read anything if the buffer size is 0, perhaps we've filled it up and the higher
        // layers haven't had a chance to consume it yet.  This will give them a chance.
        return 0;
    }

    uint32_t totalRead = 0;

    // First check to see if we've got any cached data first
    if (af_transport->have_cached_data) {
        buffer[0] = af_transport->c;
        totalRead += 1;
        af_transport->have_cached_data = false;
    }

    long start = af_utils_millis();

    bool keep_on_selectin = false;
    do {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(af_transport->socket, &read_fds);

        long now = af_utils_millis();
        struct timeval tv;
        tv.tv_sec = (MAX_TRANSFER_TIME_MS - (now - start))/1000;
        tv.tv_usec = 0; //1000*(MAX_TRANSFER_TIME_MS - (now - start));

        int result = select(af_transport->socket + 1, &read_fds, NULL, NULL, &tv);
        if (result > 0) {
            int retVal = read(af_transport->socket, buffer + totalRead, size - totalRead);
            if (retVal <= 0) {
                // Error, but since we're non-blocking those errors aren't actually errors
                if ((EAGAIN == errno || EWOULDBLOCK == errno) && retVal != 0) {
                    // all done for the moment...
                    //return 0; stephen playing...
                } else {
                    fprintf(stderr, "linux_uart_read(%d): error reading socket %d : %s\n", af_transport->socket, retVal, retVal < 0 ? strerror(errno) : "socket closed");
                    return -1;
                }
            } else {
                totalRead += retVal;
                keep_on_selectin = true;
            }
        } else {
            // timeout or error
            return -1;
        }
    } while (keep_on_selectin && totalRead < size);

#if DEBUG_UART
    fprintf(stdout, "linux_uart_read(): size %d\ndata: ", size);

    for (int i = 0; i < size; i++) {
        fprintf(stdout, "0x%X ", buffer[i]);
    }
    fprintf(stdout, "\n total read %d\n", size);
#endif

    return size;
}

af_transport_t* linux_uart_create(const char* uart_path, uint32_t baud_rate) {
    struct termios options;
    speed_t speed = B9600;

    af_transport_t *result = (af_transport_t*)malloc(sizeof(struct af_transport_t));
    result->have_cached_data = false;
    result->c = 0;

    //OPEN THE UART
    //The flags (defined in fcntl.h):
    //	Access modes (use 1 of these):
    //		O_RDONLY - Open for reading only.
    //		O_RDWR - Open for reading and writing.
    //		O_WRONLY - Open for writing only.
    //
    //	O_NDELAY / O_NONBLOCK (same function) - Enables nonblocking mode. When set read requests on the file can return immediately with a failure status
    //											if there is no input immediately available (instead of blocking). Likewise, write requests can also return
    //											immediately with a failure status if the output can't be written immediately.
    //
    //	O_NOCTTY - When set and path identifies a terminal device, open() shall not cause the terminal device to become the controlling terminal for the process.
    result->socket = open(uart_path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (-1 == result->socket) {
        fprintf(stdout, "linux_uart_create: unable to create uart socket for path %s %d:%s\n", uart_path, errno, strerror(errno));
        exit(-1); // Not much else we can do here...
    }

    //CONFIGURE THE UART
    //The flags (defined in /usr/include/termios.h - see http://pubs.opengroup.org/onlinepubs/007908799/xsh/termios.h.html):
    //	Baud rate:- B1200, B2400, B4800, B9600, B19200, B38400, B57600, B115200, B230400, B460800, B500000, B576000, B921600, B1000000, B1152000, B1500000, B2000000, B2500000, B3000000, B3500000, B4000000
    //	CSIZE:- CS5, CS6, CS7, CS8
    //	CLOCAL - Ignore modem status lines
    //	CREAD - Enable receiver
    //	IGNPAR = Ignore characters with parity errors
    //	ICRNL - Map CR to NL on input (Use for ASCII comms where you want to auto correct end of line characters - don't use for bianry comms!)
    //	PARENB - Parity enable
    //	PARODD - Odd parity (else even)
    tcgetattr(result->socket, &options);
    options.c_cflag = CS8 | CLOCAL | CREAD;
    options.c_iflag = IGNPAR;
    options.c_oflag = 0;
    options.c_lflag = 0;

    switch (baud_rate) {
        case 9600:
            speed = B9600;
            break;
        case 19200:
            speed = B19200;
            break;
        case 38400:
            speed = B38400;
            break;
        case 57600:
            speed = B57600;
            break;
        case 115200:
            speed = B115200;
            break;
        default:
            fprintf(stderr, "linux_uart_create: unhandled baud rate %d, defaulting to 9600\n", baud_rate);
            speed = B9600;
    }

    cfsetospeed(&options, speed);
    cfsetispeed(&options, speed);

    tcflush(result->socket, TCIFLUSH);
    tcsetattr(result->socket, TCSANOW, &options);

    return result;
}

void linux_uart_destroy(af_transport_t *af_transport) {
    close(af_transport->socket);
    free(af_transport);
}

void af_transport_check_for_interrupt(af_transport_t *af_transport, volatile int *interrupts_pending, bool idle) {
    if (af_transport->have_cached_data) {
        return;
    }

    uint8_t c;
    int res = read(af_transport->socket, &c, sizeof(c));
    if (res != -1) {
        if (sizeof(c) == res && c == INT_CHAR) {
            if (*interrupts_pending == 0) {
                //af_logger_println_buffer("INT");
                *interrupts_pending += 1;
            } else if (!idle) {
                // Need to save off the data we just read for the next read call
                af_transport->have_cached_data = true;
                af_transport->c = c;
            } else {
                //af_logger_println_buffer("INT(Pending)");
                // Need to save off the data we just read for the next read call
                af_transport->have_cached_data = true;
                af_transport->c = c;
            }
        } else {
            if (*interrupts_pending == 0) {
                //af_logger_print_buffer("Skipping: "); af_logger_println_formatted_value(c, AF_LOGGER_HEX);
            } else {
                // Need to save off the data we just read for the next read call
                af_transport->have_cached_data = true;
                af_transport->c = c;
            }
        }
    }
}

int af_transport_exchange_status(af_transport_t *af_transport, af_status_command_t *af_status_command_tx, af_status_command_t *af_status_command_rx) {
    int result = AF_SUCCESS;
    uint16_t len = af_status_command_get_size(af_status_command_tx);
    uint8_t bytes[len];
    uint8_t rbytes[len + 1];
    int index = 0;
    af_status_command_get_bytes(af_status_command_tx, bytes);

    for (int i=0; i < len; i++)
    {
        rbytes[i]=bytes[i];
    }
    rbytes[len]=af_status_command_get_checksum(af_status_command_tx);

    linux_uart_send(af_transport, rbytes, len + 1);

    //fprintf(stdout, "af_transport_exchange_status(): sent bytes %d\n", len + 1);

    // Skip any interrupts that may have come in.
    int read_result = linux_uart_read(af_transport, rbytes, 1);
    if (read_result < 0) {
        return AF_ERROR_TIMEOUT;
    }
    while (rbytes[0] == INT_CHAR) {
        read_result = linux_uart_read(af_transport, rbytes, 1);
        if (read_result < 0) {
            return AF_ERROR_TIMEOUT;
        }
    }

    // Okay, we have a good first char, now read the rest.
    read_result = linux_uart_read(af_transport, &rbytes[1], len);
    if (read_result < 0) {
        return AF_ERROR_TIMEOUT;
    }

    //fprintf(stdout, "af_transport_exchange_status(): recvd bytes %d\n", len + 1);

    uint8_t cmd = bytes[index++];
    if (cmd != SYNC_REQUEST && cmd != SYNC_ACK) {
        af_logger_print_buffer("exchangeStatus bad cmd: ");
        af_logger_println_formatted_value(cmd, AF_LOGGER_HEX);
        result = AF_ERROR_INVALID_COMMAND;
    }

    af_status_command_set_bytes_to_send(af_status_command_rx, rbytes[index + 0] | (rbytes[index + 1] << 8));
    af_status_command_set_bytes_to_recv(af_status_command_rx, rbytes[index + 2] | (rbytes[index + 3] << 8));
    af_status_command_set_checksum(af_status_command_rx, rbytes[index+4]);

    //fprintf(stdout, "rx command send %d, recv %d\n", af_status_command_get_bytes_to_send(af_status_command_rx), af_status_command_get_bytes_to_recv(af_status_command_rx));

    return result;
}

int af_transport_write_status(af_transport_t *af_transport, af_status_command_t *af_status_command) {
    int result = AF_SUCCESS;
    uint16_t len = af_status_command_get_size(af_status_command);
    uint8_t bytes[len];
    uint8_t rbytes[len+1];
    int index = 0;
    af_status_command_get_bytes(af_status_command, bytes);

    for (int i=0;i<len;i++)
    {
        rbytes[i]=bytes[i];
    }
    rbytes[len]=af_status_command_get_checksum(af_status_command);

    linux_uart_send(af_transport, rbytes, len + 1);

    uint8_t cmd = rbytes[index++];
    if (cmd != SYNC_REQUEST && cmd != SYNC_ACK) {
        af_logger_print_buffer("writeStatus bad cmd: ");
        af_logger_println_formatted_value(cmd, AF_LOGGER_HEX);
        result = AF_ERROR_INVALID_COMMAND;
    }

    //af_status_command_dump(c);
    //af_status_command_dump_bytes(c);

    return result;
}

void af_transport_send_bytes_offset(af_transport_t *af_transport, uint8_t *bytes, uint16_t *bytes_to_send, uint16_t *offset) {
    uint16_t len = 0;

    len = *bytes_to_send;

    linux_uart_send(af_transport, bytes, len);

    *offset += len;
    *bytes_to_send -= len;
}

int af_transport_recv_bytes_offset(af_transport_t *af_transport, uint8_t **bytes, uint16_t *bytes_len, uint16_t *bytes_to_recv, uint16_t *offset) {
    uint16_t len = 0;

    len = *bytes_to_recv;

    if (*offset == 0) {
        *bytes_len = *bytes_to_recv;
        *bytes = (uint8_t*)malloc(*bytes_len);
    }

    uint8_t * start = *bytes + *offset;

    int result = linux_uart_read(af_transport, start, len);
    if (result < 0) {
        return AF_ERROR_TIMEOUT;
    }

    *offset += len;
    *bytes_to_recv -= len;

    return AF_SUCCESS;
}