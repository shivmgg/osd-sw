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

// #include <osd/module.h>
// #include <osd/osd.h>
// #include <osd/reg.h>
// #include "osd-private.h"

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int osd_result;

/** Return code: The operation was successful */
#define OSD_OK 0
/** Return code: Generic (unknown) failure */
#define OSD_ERROR_FAILURE -1
/** Return code: debug system returned a failure */
#define OSD_ERROR_DEVICE_ERROR -2
/** Return code: received invalid or malformed data from device */
#define OSD_ERROR_DEVICE_INVALID_DATA -3
/** Return code: failed to communicate with device */
#define OSD_ERROR_COM -4
/** Return code: operation timed out */
#define OSD_ERROR_TIMEDOUT -5
/** Return code: not connected to the device */
#define OSD_ERROR_NOT_CONNECTED -6
/** Return code: this is a partial result, not all requested data was obtained */
#define OSD_ERROR_PARTIAL_RESULT -7
/** Return code: operation aborted */
#define OSD_ERROR_ABORTED -8
/** Return code: connection failed */
#define OSD_ERROR_CONNECTION_FAILED -9
/** Return code: Out of memory */
#define OSD_ERROR_OOM -11
/** Return code: file operation failed */
#define OSD_ERROR_FILE -12
/** Return code: memory verification failed */
#define OSD_ERROR_MEM_VERIFY_FAILED -13
/** Return code: unexpected module type */
#define OSD_ERROR_WRONG_MODULE -14

/**
 * Return true if |rv| is an error code
 */
#define OSD_FAILED(rv) ((rv) < 0)
/**
 * Return true if |rv| is a successful return code
 */
#define OSD_SUCCEEDED(rv) ((rv) >= 0)
#define SERVER_PORT 5555
#define BUFF_SIZE 1024


struct connection {
    int fd;
    char *name;
    char *port;
    struct sockaddr_in sin;
    char buffer[BUFF_SIZE];
    int buf_cnt;
    char *buf_p;
    int closed;
};

osd_result add_connection(char *name, char *port);
void free_connection(struct connection *c);
void fetch_data(struct connection *c, int client_fd);
osd_result get_data(struct connection *c, int client_fd);
osd_result put_data(struct connection *c, int client_fd, char *data, int len);
osd_result get_char(struct connection *c, int client_fd, int *ch);
osd_result get_packet(struct connection *c, int client_fd, char *buffer,
                      int *len);
osd_result validate_packet(struct connection *c, int client_fd,
                           int *ver_checksum, int *len, char *buffer);
int dectohex(int packet_char);

int main(int argc, char const *argv[])
{
    /* code */
    add_connection("127.0.0.1","5555");
    return 0;
}

osd_result add_connection(char *name, char *port)
{
    int sockoptval = 1;
    struct connection *c = calloc(1, sizeof(struct connection));
    assert(c);

    c->name = strdup(name);
    c->port = strdup(port);
    c->fd = socket(AF_INET, SOCK_STREAM, 0);

    if (OSD_FAILED(c->fd)) {
        free_connection(c);
        return OSD_ERROR_CONNECTION_FAILED;
    }

    setsockopt(c->fd, SOL_SOCKET, SO_REUSEADDR, &sockoptval, sizeof(int));

    memset(&c->sin, 0, sizeof(c->sin));
    c->sin.sin_family = AF_INET;
    c->sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    c->sin.sin_port = htons(SERVER_PORT);

    if (OSD_FAILED(bind(c->fd, (struct sockaddr *)&c->sin, sizeof(c->sin)))) {
        close(c->fd);
        free_connection(c);
        return OSD_ERROR_CONNECTION_FAILED;
    }

    if (OSD_FAILED(listen(c->fd, 1))) {
        close(c->fd);
        free_connection(c);
        return OSD_ERROR_CONNECTION_FAILED;
    }

    int client_fd;
    struct sockaddr_in addr_in;
    addr_in.sin_port = 0;
    socklen_t addr_in_size = sizeof(addr_in);

    getsockname(c->fd, (struct sockaddr *)&addr_in, &addr_in_size);
    printf("server started on %s, listening on port %d\n", name,
           ntohs(addr_in.sin_port));

    while (1) {
        client_fd = accept(c->fd, (struct sockaddr *)&addr_in, &addr_in_size);
        if (OSD_FAILED(client_fd)) {
            int rev = close(client_fd);
            if (OSD_SUCCEEDED(rev)) {
                break;
            }
        }

        printf("Server got connection from client %s\n",
               inet_ntoa(addr_in.sin_addr));
        char buffer[BUFF_SIZE];
        int len;
        get_data(c,client_fd);
        get_data(c, client_fd);
        get_packet(c,client_fd, buffer, &len);
        printf("%s\n", buffer);
        if (OSD_SUCCEEDED(close(client_fd))) {
            break;
        }
    }

    close(c->fd);

    return OSD_OK;
}

osd_result get_data(struct connection *c, int client_fd)
{
    memset(c->buffer, 0, sizeof c->buffer);
    c->buf_cnt = read(client_fd, c->buffer, BUFF_SIZE);
    
    if (OSD_FAILED(c->buf_cnt)) {
        return OSD_ERROR_CONNECTION_FAILED;
    } else {
        if (c->buf_cnt > 0) {
            printf("Server:Packet Received %s\n", c->buffer);
            printf("Size of Packet:%d\n", c->buf_cnt);
            return OSD_OK;
        }
        if (c->buf_cnt == 0) {
            c->closed = 1;
            return OSD_ERROR_FAILURE;
        }
    }

    return OSD_OK;
}

osd_result put_data(struct connection *c, int client_fd, char *data, int len)
{
    if (c->closed == 1) {
        return OSD_ERROR_NOT_CONNECTED;
    }
    int wlen = write(client_fd, data, len);
    if (wlen == len) {
        return OSD_OK;
    }

    return OSD_ERROR_NOT_CONNECTED;
}

osd_result get_char(struct connection *c, int client_fd, int *ch)
{
    osd_result rv;

    c->buf_p = c->buffer;
    c->buf_cnt--;
    if (OSD_FAILED(c->buf_cnt)) {
        return OSD_ERROR_FAILURE;
    }
    *ch = *(c->buf_p++);

    return OSD_OK;
}

osd_result validate_packet(struct connection *c, int client_fd,
                           int *ver_checksum, int *len, char *buffer)
{
    unsigned char val_checksum = 0;
    char packet_checksum[3];
    int packet_char;
    int cnt = 0;
    osd_result rv;

    char *buf_p = c->buf_p;
    int buf_cnt = c->buf_cnt;

    // packet-format: $packet-data#checksum
    int i = 0;
    char *buf = buf_p;
    int done = 0;
    // traversing through the obtained packet till we obtained '#'
    while (1) {
        packet_char = *buf++;
        i++;

        if (packet_char == '#') {
            done = 1;
            break;
        }
        /*Any escaped byte (here, '}') is transmitted as the escape
        * character followed by the original character XORed with 0x20.
        */
        if (packet_char == '}') {
            val_checksum += packet_char & 0xff;
            packet_char = *buf++;
            i++;
            val_checksum += packet_char & 0xff;
            buffer[cnt++] = (packet_char ^ 0x20) & 0xff;
        } else {
            val_checksum += packet_char & 0xff;
            buffer[cnt++] = packet_char & 0xff;
        }
    }

    *len = cnt;
    packet_char = *buf++;
    packet_checksum[0] = packet_char;
    packet_char = *buf;
    packet_checksum[1] = packet_char;
    packet_checksum[2] = 0;
    *ver_checksum = (val_checksum == strtoul(packet_checksum, NULL, 16));

    return OSD_OK;
}

osd_result get_packet(struct connection *c, int client_fd, char *buffer,
                      int *len)
{
    int packet_char;
    osd_result rv;

    do {
        rv = get_char(c, client_fd, &packet_char);
        if (OSD_FAILED(rv)) {
            return rv;
        }
    } while (packet_char != '$');

    int ver_checksum = 0;
    rv = validate_packet(c, client_fd, &ver_checksum, len, buffer);

    if (OSD_FAILED(rv)) {
        return rv;
    } else {
        if (ver_checksum == 1) {
            rv = put_data(c, client_fd, "+", 1);
        } else {
            rv = put_data(c, client_fd, "-", 1);
        }
        if (OSD_FAILED(rv)) {
            return rv;
        }
    }
    return OSD_OK;
}

osd_result put_packet(struct connection *c, int client_fd, char *buffer,
                      int len) 
{
 
    char packet_buffer[len + 3];
    int packet_checksum = 0;
    osd_result rv;
     
    while (1) {
        packet_buffer[0] = '$';
        memcpy(packet_buffer + 1, buffer, len);
        int j = len + 1;
        packet_buffer[j++] = '#';
        for (int i=0; i < len; i++) {
            packet_checksum += buffer[i];
        }
        packet_buffer[j++] = dectohex((packet_checksum >> 4) & 0xf);
        packet_buffer[j] = dectohex(packet_checksum & 0xf);
        
        rv = put_data(c, client_fd, packet_buffer, len+4);
        if (OSD_FAILED(rv)) {
            return OSD_ERROR_FAILURE;
        }
        
        rv = get_data(c, client_fd);
        if (OSD_FAILED(rv)) {
            return OSD_ERROR_FAILURE; 
        }
        
        char reply = c->buffer[0];  
        if (reply == '+') {
            break;
        } else {
            return OSD_ERROR_FAILURE;
        }
    }

    return OSD_OK;  
}

int dectohex(int packet_char) 
{ 
    if (packet_char < 10) {
        return packet_char + '0';
    } else {
        return packet_char - 10 + 'a';
    } 

}

void free_connection(struct connection *c)
{
    free(c->name);
    free(c->port);
    free(c);
}
