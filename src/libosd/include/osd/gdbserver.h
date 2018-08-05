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

#ifndef OSD_GDBSERVER_H
#define OSD_GDBSERVER_H

#include <osd/hostmod.h>
#include <osd/osd.h>

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup libosd-gdbserver OSD-GDB server utility
 * @ingroup libosd
 *
 * @{
 */

struct osd_gdbserver_ctx;

/**
 * Indicates the default port for connecting to GDB
 */
#define OSD_GDBSERVER_PORT_DEFAULT 5555

/**
 * Indicates the size of the RSP packet buffer
 */
#define OSD_GDBSERVER_BUFF_SIZE 1024

/**
 * Create a new context object
 *
 * @param ctx context object
 * @param log_ctx logging context
 * @param host_controller_address ZeroMQ endpoint of the host controller
 * @param cdm_di_addr DI address of the CDM module
 * @param mam_di_addr DI address of the MAM module
 * @return OSD_OK if initialization was successful,
 *         any other return code indicates an error
 */
osd_result osd_gdbserver_new(struct osd_gdbserver_ctx **ctx,
                             struct osd_log_ctx *log_ctx,
                             const char *host_controller_address,
                             uint16_t cdm_di_addr, uint16_t mam_di_addr);

/**
 * Connect to the GDB client and the host controller
 *
 * @param ctx the osd_gdbserver_ctx context object
 * @return OSD_OK on success, any other value indicates an error
 *
 * @see osd_gdbserver_disconnect()
 */
osd_result osd_gdbserver_connect(struct osd_gdbserver_ctx *ctx);

/**
 * Stop the connection with GDB client and the host controller
 *
 * @param ctx the osd_gdbserver_ctx context object
 * @return OSD_OK on success, any other value indicates an error
 *
 * @see osd_gdbserver_connect()
 */
osd_result osd_gdbserver_disconnect(struct osd_gdbserver_ctx *ctx);

/**
 * Free the context object
 *
 * By calling this function all resources associated with the context object
 * are freed and the ctx_p itself is NULLed.
 *
 * @param ctx_p the context object
 */
void osd_gdbserver_free(struct osd_gdbserver_ctx **ctx_p);

/**
 * @copydoc osd_hostmod_is_connected()
 */
bool osd_gdbserver_is_connected_hostmod(struct osd_gdbserver_ctx *ctx);

/**
 * Set the port number for TCP communication with GDB
 *
 * @param ctx the context object
 * @param port the port number the server will bind to
 * @return OSD_OK on success, any other value indicates an error
 *
 * @see osd_gdbserver_set_addr()
 */
void osd_gdbserver_set_port(struct osd_gdbserver_ctx *ctx, int port);

/**
 * Set the IP address for TCP communication with GDB
 *
 * @param ctx the context object
 * @param address the address the server will bind to
 * @return OSD_OK on success, any other value indicates an error
 *
 * @see osd_gdbserver_set_port()
 */
void osd_gdbserver_set_addr(struct osd_gdbserver_ctx *ctx, int address);

/**@}*/ /* end of doxygen group libosd-gdbserver */

#ifdef __cplusplus
}
#endif

#endif  // OSD_GDBSERVER_H