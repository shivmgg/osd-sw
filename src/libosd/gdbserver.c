/* Copyright 2018 The Open SoC Debug Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <osd/cl_cdm.h>
#include <osd/cl_mam.h>
#include <osd/gdbserver.h>
#include <osd/module.h>
#include <osd/osd.h>
#include <osd/reg.h>
#include "gdbserver-private.h"
#include "osd-private.h"

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

pthread_t osd_gdbserver_thread;

/**
 * OSD-GDB server context
 */
struct osd_gdbserver_ctx {
    struct osd_hostmod_ctx *hostmod_ctx;
    struct osd_log_ctx *log_ctx;
    struct osd_cdm_desc cdm_desc;
    struct osd_mem_desc mem_desc;
    uint16_t cdm_di_addr;
    uint16_t mam_di_addr;
    int fd;
    int port;
    int addr;
    int client_fd;
    char buffer[OSD_GDBSERVER_BUFF_SIZE];
    int buf_cnt;
    char *buf_p;
    int closed;
    osd_result rv;
};

API_EXPORT
osd_result osd_gdbserver_new(struct osd_gdbserver_ctx **ctx,
                             struct osd_log_ctx *log_ctx,
                             const char *host_controller_address,
                             uint16_t cdm_di_addr, uint16_t mam_di_addr)
{
    osd_result rv;

    struct osd_gdbserver_ctx *c = calloc(1, sizeof(struct osd_gdbserver_ctx));
    assert(c);

    c->log_ctx = log_ctx;
    c->cdm_di_addr = cdm_di_addr;
    c->mam_di_addr = mam_di_addr;

    struct osd_hostmod_ctx *hostmod_ctx;
    rv = osd_hostmod_new(&hostmod_ctx, log_ctx, host_controller_address, NULL,
                         NULL);
    assert(OSD_SUCCEEDED(rv));
    c->hostmod_ctx = hostmod_ctx;

    *ctx = c;

    return OSD_OK;
}

/**
 * Converts decimal number to hexadecimal number
 */
static char dectohex(int dec_val)
{
    if (dec_val >= 10 && dec_val <= 15) {
        return dec_val - 10 + 'a';
    } else if (dec_val >= 0 && dec_val <= 9) {
        return dec_val + '0';
    }
    return '\0';
}

/**
 * Converts hexadecimal number to decimal number
 */
static int hextodec(char hex_val)
{
    if (hex_val >= 'a' && hex_val <= 'f') {
        return hex_val + 10 - 'a';
    } else if (hex_val >= 'A' && hex_val <= 'F') {
        return hex_val + 10 - 'A';
    } else if (hex_val >= '0' && hex_val <= '9') {
        return hex_val - '0';
    }
    return -1;
}

API_EXPORT
void mem2hex(uint8_t *mem_val, size_t mem_len, uint8_t *mem_hex)
{
    size_t i;
    for (i = 0; i < 2 * mem_len; i++) {
        uint8_t temp = (mem_val[i / 2] >> (4 * ((i + 1) % 2))) & 0x0f;
        mem_hex[i] = dectohex(temp);
    }
    mem_hex[i] = '\0';
}

API_EXPORT
void hex2mem(uint8_t *mem_hex, size_t mem_len, uint8_t *mem_val)
{
    size_t i;
    uint8_t temp;
    memset(mem_val, 0, mem_len);
    for (i = 0; i < 2 * mem_len; i++) {
        temp = hextodec(mem_hex[i]);
        mem_val[i / 2] |= temp << (4 * ((i + 1) % 2));
    }
    mem_val[mem_len] = 0;
}

API_EXPORT
void osd_gdbserver_set_port(struct osd_gdbserver_ctx *ctx, int port)
{
    if (port == -1) {
        ctx->port = OSD_GDBSERVER_PORT_DEFAULT;
    } else {
        ctx->port = port;
    }
}

API_EXPORT
void osd_gdbserver_set_addr(struct osd_gdbserver_ctx *ctx, int address)
{
    if (address == -1) {
        ctx->addr = INADDR_LOOPBACK;
    } else {
        ctx->addr = address;
    }
}

API_EXPORT
bool osd_gdbserver_is_connected_hostmod(struct osd_gdbserver_ctx *ctx)
{
    return osd_hostmod_is_connected(ctx->hostmod_ctx);
}

API_EXPORT
void osd_gdbserver_free(struct osd_gdbserver_ctx **ctx_p)
{
    assert(ctx_p);
    struct osd_gdbserver_ctx *ctx = *ctx_p;
    if (!ctx) {
        return;
    }

    osd_hostmod_free(&ctx->hostmod_ctx);

    free(ctx);
    *ctx_p = NULL;
}

static osd_result osd_gdbserver_read_data(struct osd_gdbserver_ctx *ctx)
{
    memset(ctx->buffer, 0, sizeof ctx->buffer);
    ctx->buf_cnt =
        recv(ctx->client_fd, ctx->buffer, OSD_GDBSERVER_BUFF_SIZE, 0);

    if (OSD_FAILED(ctx->buf_cnt)) {
        return OSD_ERROR_CONNECTION_FAILED;
    } else {
        if (ctx->buf_cnt > 0) {
            printf("Server:Packet Received %s\n", ctx->buffer);
            printf("Size of Packet:%d\n", ctx->buf_cnt);
            return OSD_OK;
        }
        if (ctx->buf_cnt == 0) {
            ctx->closed = 1;
            return OSD_ERROR_FAILURE;
        }
    }

    return OSD_OK;
}

static osd_result osd_gdbserver_write_data(struct osd_gdbserver_ctx *ctx,
                                           char *data, int len)
{
    if (ctx->closed == 1) {
        return OSD_ERROR_NOT_CONNECTED;
    }
    printf("Server:Data send- %s", data);
    int wlen = write(ctx->client_fd, data, len);
    if (wlen == len) {
        return OSD_OK;
    }

    return OSD_ERROR_NOT_CONNECTED;
}

static osd_result get_char(struct osd_gdbserver_ctx *ctx, int *ch)
{
    ctx->buf_p = ctx->buffer;
    ctx->buf_cnt--;
    if (OSD_FAILED(ctx->buf_cnt)) {
        return OSD_ERROR_FAILURE;
    }
    *ch = *(ctx->buf_p++);

    return OSD_OK;
}

API_EXPORT
bool validate_rsp_packet(char *packet_buffer, int packet_len,
                         int *packet_data_len, char *packet_data)
{
    unsigned char val_checksum = 0;
    char packet_checksum[3];
    int packet_char;
    int cnt = 0;
    char *buf = packet_buffer;

    // packet-format: $packet-data#checksum
    // traversing through the obtained packet till we obtained '#'
    while (packet_len >= 2) {
        packet_char = *buf++;

        if (packet_char == '#') {
            break;
        }
        /* Any escaped byte (here, '}') is transmitted as the escape
         * character followed by the original character XORed with 0x20.
         */
        if (packet_char == '}') {
            val_checksum += packet_char;
            packet_char = *buf++;
            packet_len--;
            val_checksum += packet_char;
            packet_data[cnt++] = (packet_char ^ 0x20);
        } else {
            val_checksum += packet_char;
            packet_data[cnt++] = packet_char;
        }
        packet_len--;
    }

    packet_char = *buf++;
    packet_checksum[0] = packet_char;
    packet_char = *buf;
    packet_checksum[1] = packet_char;
    packet_checksum[2] = 0;

    packet_data[cnt] = '\0';
    *packet_data_len = cnt;
    bool ver_checksum = (val_checksum == strtoul(packet_checksum, NULL, 16));

    return ver_checksum;
}

static osd_result receive_rsp_packet(struct osd_gdbserver_ctx *ctx,
                                     char *packet_data, int *packet_data_len)
{
    int packet_char;
    osd_result rv;

    do {
        rv = get_char(ctx, &packet_char);
        if (OSD_FAILED(rv)) {
            return rv;
        }
    } while (packet_char != '$');

    char *packet_buffer = ctx->buf_p;
    int packet_len = ctx->buf_cnt;
    bool ver_checksum = validate_rsp_packet(packet_buffer, packet_len,
                                            packet_data_len, packet_data);

    if (ver_checksum == 1) {
        rv = osd_gdbserver_write_data(ctx, "+", 1);
        if (OSD_FAILED(rv)) {
            return rv;
        }
    } else {
        rv = osd_gdbserver_write_data(ctx, "-", 1);
        if (OSD_FAILED(rv)) {
            return rv;
        }
        return OSD_ERROR_FAILURE;
    }

    return OSD_OK;
}

API_EXPORT
osd_result encode_rsp_packet(char *packet_data, int packet_data_len,
                             char *packet_buffer)
{
    int packet_checksum = 0;
    packet_buffer[0] = '$';

    memcpy(packet_buffer + 1, packet_data, packet_data_len);
    int j = packet_data_len + 1;

    packet_buffer[j++] = '#';
    for (int i = 0; i < packet_data_len; i++) {
        packet_checksum += packet_data[i];
    }
    packet_buffer[j++] = dectohex((packet_checksum >> 4) & 0xf);
    packet_buffer[j++] = dectohex(packet_checksum & 0xf);
    packet_buffer[j] = '\0';

    return OSD_OK;
}

static osd_result send_rsp_packet(struct osd_gdbserver_ctx *ctx,
                                  char *packet_data, int packet_data_len)
{
    char packet_buffer[packet_data_len + 5];
    osd_result rv;

    encode_rsp_packet(packet_data, packet_data_len, packet_buffer);

    rv = osd_gdbserver_write_data(ctx, packet_buffer, packet_data_len + 4);
    if (OSD_FAILED(rv)) {
        return OSD_ERROR_FAILURE;
    }

    rv = osd_gdbserver_read_data(ctx);
    if (OSD_FAILED(rv)) {
        return OSD_ERROR_FAILURE;
    }

    char reply = ctx->buffer[0];
    if (reply == '+') {
        return OSD_OK;
    }

    return OSD_ERROR_FAILURE;
}

static osd_result gdb_read_general_registers_cmd(struct osd_gdbserver_ctx *ctx,
                                                 char *packet_buffer,
                                                 int packet_len)
{
    osd_result rv;
    // SPR register (GROUP 0 REG_NUM 1024) address mapped as GPR0 in OR1K
    uint16_t reg_addr = 0x400;

    rv =
        osd_cl_cdm_get_desc(ctx->hostmod_ctx, ctx->cdm_di_addr, &ctx->cdm_desc);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    int core_reg_len = ctx->cdm_desc.core_data_width;
    size_t reg_read_result[32];
    // + 1 for null character
    // used for storing the read register value of all the GPRs
    char *reg_packet = malloc((core_reg_len / 8) * 32 + 1);

    // read the value of each GPR from the CPU core and
    // store it in the register packet.
    for (int i = 0; i < 32; i++) {
        rv = cl_cdm_cpureg_read(ctx->hostmod_ctx, &ctx->cdm_desc,
                                &reg_read_result[i], reg_addr + i, 0);
        if (OSD_FAILED(rv)) {
            return rv;
        }

        char *reg_val = malloc((core_reg_len / 8) + 1);
        sprintf(reg_val, "%02lx", reg_read_result[i]);
        strcat(reg_packet, reg_val);
        free(reg_val);
    }

    rv = send_rsp_packet(ctx, reg_packet, (core_reg_len / 8) * 32 + 1);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    free(reg_packet);

    return OSD_OK;
}

static osd_result gdb_write_general_registers_cmd(struct osd_gdbserver_ctx *ctx,
                                                  char *packet, int packet_len)
{
    osd_result rv;
    rv =
        osd_cl_cdm_get_desc(ctx->hostmod_ctx, ctx->cdm_di_addr, &ctx->cdm_desc);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    // increment by 1 to skip initial char 'G'
    packet++;

    // SPR register (GROUP 0 REG_NUM 1024) address mapped as GPR0 in OR1K
    uint16_t reg_addr = 0x400;
    int core_reg_len = ctx->cdm_desc.core_data_width;

    // write the value of each GPR in the CPU core
    for (int i = 0; i < 32; i++) {
        char cur_reg_val[core_reg_len / 4 + 1];
        for (int j = 0; j < core_reg_len / 4; j++) {
            cur_reg_val[j] = packet[i * core_reg_len + j];
        }

        cur_reg_val[core_reg_len / 4] = '\0';
        size_t reg_val = strtoul(cur_reg_val, NULL, 16);
        rv = cl_cdm_cpureg_write(ctx->hostmod_ctx, &ctx->cdm_desc, &reg_val,
                                 reg_addr + i, 0);
        if (OSD_FAILED(rv)) {
            return rv;
        }
    }

    rv = send_rsp_packet(ctx, "OK", 2);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    return OSD_OK;
}

static osd_result gdb_read_register_cmd(struct osd_gdbserver_ctx *ctx,
                                        char *packet, int packet_len)
{
    osd_result rv;
    uint16_t reg_addr = strtoul(packet + 1, NULL, 16);

    rv =
        osd_cl_cdm_get_desc(ctx->hostmod_ctx, ctx->cdm_di_addr, &ctx->cdm_desc);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    int core_reg_len = ctx->cdm_desc.core_data_width;
    size_t reg_read_result;
    rv = cl_cdm_cpureg_read(ctx->hostmod_ctx, &ctx->cdm_desc, &reg_read_result,
                            reg_addr, 0);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    char *reg_val = malloc(core_reg_len / 8 + 1);
    sprintf(reg_val, "%02lx", reg_read_result);
    rv = send_rsp_packet(ctx, reg_val, core_reg_len / 8 + 1);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    free(reg_val);

    return OSD_OK;
}

static osd_result gdb_write_register_cmd(struct osd_gdbserver_ctx *ctx,
                                         char *packet, int packet_len)
{
    osd_result rv;
    char *equal_separator;
    uint16_t reg_addr = strtoul(packet + 1, &equal_separator, 16);
    rv =
        osd_cl_cdm_get_desc(ctx->hostmod_ctx, ctx->cdm_di_addr, &ctx->cdm_desc);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    if (*equal_separator != '=') {
        return OSD_ERROR_FAILURE;
    }

    size_t reg_val = strtoul(equal_separator + 1, NULL, 16);
    rv = cl_cdm_cpureg_write(ctx->hostmod_ctx, &ctx->cdm_desc, &reg_val,
                             reg_addr, 0);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    rv = send_rsp_packet(ctx, "OK", 2);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    return OSD_OK;
}

static osd_result gdb_read_memory_cmd(struct osd_gdbserver_ctx *ctx,
                                      char *packet, int packet_len)
{
    osd_result rv;
    uint64_t mem_addr;
    size_t mem_len;
    char *comma_separator;

    rv = osd_cl_mam_get_mem_desc(ctx->hostmod_ctx, ctx->mam_di_addr,
                                 &ctx->mem_desc);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    packet++;
    mem_addr = strtoul(packet, &comma_separator, 16);
    if (*comma_separator != ',') {
        return OSD_ERROR_FAILURE;
    }

    mem_len = strtoul(comma_separator + 1, NULL, 16);
    if (!mem_len) {
        return OSD_ERROR_FAILURE;
    }

    size_t mem_read_result;
    rv = osd_cl_mam_read(&ctx->mem_desc, ctx->hostmod_ctx, &mem_read_result,
                         mem_len, mem_addr);

    // Each byte is represented as two hex characters
    uint8_t *mem_packet_content = malloc(mem_len * 2 + 1);
    uint8_t *mem_val = (uint8_t *)&mem_read_result;
    mem2hex(mem_val, mem_len, mem_packet_content);

    rv = send_rsp_packet(ctx, (char *)mem_packet_content, mem_len * 2 + 1);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    free(mem_packet_content);
    return OSD_OK;
}

static osd_result gdb_write_memory_cmd(struct osd_gdbserver_ctx *ctx,
                                       char *packet, int packet_len)
{
    osd_result rv;
    uint64_t mem_addr;
    size_t mem_len;
    char *comma_separator;
    char *colon_separator;

    rv = osd_cl_mam_get_mem_desc(ctx->hostmod_ctx, ctx->mam_di_addr,
                                 &ctx->mem_desc);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    packet++;
    mem_addr = strtoul(packet, &comma_separator, 16);
    if (*comma_separator != ',') {
        return OSD_ERROR_FAILURE;
    }

    mem_len = strtoul(comma_separator + 1, &colon_separator, 16);
    if (!mem_len) {
        return OSD_ERROR_FAILURE;
    }

    if (*colon_separator != ':') {
        return OSD_ERROR_FAILURE;
    }

    uint8_t *mem_packet_content = (uint8_t *)colon_separator + 1;
    // Each byte is represented as two hex characters
    uint8_t *mem_write_result = malloc(mem_len);
    hex2mem(mem_packet_content, mem_len, mem_write_result);

    rv = osd_cl_mam_write(&ctx->mem_desc, ctx->hostmod_ctx, mem_write_result,
                          mem_len, mem_addr);

    free(mem_write_result);

    rv = send_rsp_packet(ctx, "OK", 2);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    return OSD_OK;
}

static osd_result handle_rsp_packet(void *arg)
{
    struct osd_gdbserver_ctx *ctx = (struct osd_gdbserver_ctx *)arg;
    osd_result rv;

    struct sockaddr_in addr_in;
    addr_in.sin_port = 0;
    socklen_t addr_in_size = sizeof(addr_in);

    getsockname(ctx->fd, (struct sockaddr *)&addr_in, &addr_in_size);
    printf("server started listening on port %d\n", ntohs(addr_in.sin_port));

    ctx->client_fd =
        accept(ctx->fd, (struct sockaddr *)&addr_in, &addr_in_size);

    if (OSD_FAILED(ctx->client_fd)) {
        close(ctx->client_fd);
        return OSD_ERROR_FAILURE;
    }

    printf("Server got connection from client %s\n",
           inet_ntoa(addr_in.sin_addr));

    int packet_len;
    char rsp_packet_buffer[OSD_GDBSERVER_BUFF_SIZE];

    ctx->rv = osd_gdbserver_read_data(ctx);
    if (OSD_FAILED(ctx->rv)) {
        return ctx->rv;
    }

    ctx->rv = osd_gdbserver_write_data(ctx, "$p0007#37", 9);
    if (OSD_FAILED(ctx->rv)) {
        return ctx->rv;
    }
    // rv = osd_gdbserver_read_data(ctx);
    // if (OSD_FAILED(rv)) {
    //     return rv;
    // }

    // rv = receive_rsp_packet(ctx, rsp_packet_buffer, &packet_len);
    // if (OSD_FAILED(rv)) {
    //     return rv;
    // }

    // if (packet_len > 0) {
    //     switch (rsp_packet_buffer[0]) {
    //         case '?':
    //             break;
    //         case 'm':
    //             rv = gdb_read_memory_cmd(ctx, rsp_packet_buffer, packet_len);
    //             break;
    //         case 'M':
    //             rv = gdb_write_memory_cmd(ctx, rsp_packet_buffer,
    //             packet_len);
    //             break;
    //         case 'g':
    //             rv = gdb_read_general_registers_cmd(ctx, rsp_packet_buffer,
    //             	                                packet_len);
    //             break;
    //         case 'G':
    //             rv = gdb_write_general_registers_cmd(ctx, rsp_packet_buffer,
    //             	                                 packet_len);
    //             break;
    //         case 'p':
    //             rv = gdb_read_register_cmd(ctx, rsp_packet_buffer,
    //             packet_len);
    //             break;
    //         case 'P':
    //             rv = gdb_write_register_cmd(ctx, rsp_packet_buffer,
    //             packet_len);
    //             break;
    //         case 'z':
    //         case 'Z':
    //         case 'c':
    //         case 's':
    //         default:
    //             // Unsupported or unknown packet
    //             osd_gdbserver_write_data(ctx, NULL, 0);
    //             break;
    //     }
    // }

    return OSD_OK;
}

static void *gdbserver_thread_routine(void *arg)
{
    handle_rsp_packet(arg);
    struct osd_gdbserver_ctx *ctx = (struct osd_gdbserver_ctx *)arg;
    pthread_exit(arg);

    return NULL;
}

API_EXPORT
osd_result osd_gdbserver_connect(struct osd_gdbserver_ctx *ctx)
{
    osd_result rv = osd_hostmod_connect(ctx->hostmod_ctx);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    int sockoptval = 1;

    ctx->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (OSD_FAILED(ctx->fd)) {
        osd_gdbserver_free(&ctx);
        return OSD_ERROR_CONNECTION_FAILED;
    }

    setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR, &sockoptval, sizeof(int));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(ctx->addr);
    sin.sin_port = htons(ctx->port);

    rv = bind(ctx->fd, (struct sockaddr *)&sin, sizeof(sin));
    if (OSD_FAILED(rv)) {
        close(ctx->fd);
        osd_gdbserver_free(&ctx);
        return OSD_ERROR_CONNECTION_FAILED;
    }

    rv = listen(ctx->fd, 1);
    if (OSD_FAILED(rv)) {
        close(ctx->fd);
        osd_gdbserver_free(&ctx);
        return OSD_ERROR_CONNECTION_FAILED;
    }

    // Used for sending/receiving data between GDB and OSD-GDB server
    rv = pthread_create(&osd_gdbserver_thread, 0, gdbserver_thread_routine,
                        (void *)ctx);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    return OSD_OK;
}

API_EXPORT
osd_result osd_gdbserver_disconnect(struct osd_gdbserver_ctx *ctx)
{
    close(ctx->fd);
    pthread_join(osd_gdbserver_thread, (void *)&ctx);

    ctx = ((struct osd_gdbserver_ctx *)ctx);
    if (OSD_FAILED(ctx->rv)) {
        return ctx->rv;
    }

    osd_result rv = osd_hostmod_disconnect(ctx->hostmod_ctx);
    if (OSD_FAILED(rv)) {
        return rv;
    }

    return OSD_OK;
}