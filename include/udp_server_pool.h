#ifndef _UDP_SERVER_POOL_H_
#define _UDP_SERVER_POOL_H_

/**
 * Copyright 2014 Federico Casares <warptrosse@gmail.com>
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
 *
 * @file udp_server_pool.h
 */

#include "udp_server_err.h"
#include "udp_server_types.h"
#include <sys/types.h>

typedef void (*udps_post_fork_fnc_t)(void);

/**
 * Process status.
 */
typedef enum udps_pool_proc_status {
    udps_pool_proc_status_ninit,  /**< The process was not initialized. */
    udps_pool_proc_status_idle,   /**< The process is available to start
                                     working. */
    udps_pool_proc_status_working /**< The process is currently working. */
} udps_pool_proc_status_t;

/**
 * Initialize the UDP server processes pool.
 * @param[in] numpfc The initial number of processes to preforked.
 * @param[in] pff The function to be called after a fork. Generally,
 *  This function should wait in accept state.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
udps_err_t udps_pool_init(uchar numpfc, udps_post_fork_fnc_t pff);

/**
 * Updates processes pool.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
udps_err_t udps_pool_update(void);

/**
 * Close the UDP server processes pool.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
udps_err_t udps_pool_close(void);

/**
 * Set process status.
 * @param[in] pid Proces identifier.
 * @param[in] pstatus New process status.
 */
void udps_pool_set_process_status(pid_t pid, udps_pool_proc_status_t pstatus);

#endif /* _UDP_SERVER_POOL_H_ */
