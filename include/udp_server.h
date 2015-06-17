#ifndef _UDP_SERVER_H_
#define _UDP_SERVER_H_

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
 * @file udp_server.h
 */

#include "udp_server_err.h"
#include "udp_server_types.h"
#include <sys/types.h>

/**
 * Initialize the UDP server in the specified port.
 * @param[in] port The port to listen.
 * @param[in] nclients The initial number of processes to preforked.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
udps_err_t udps_init(ushort port, uchar nclients);

/**
 * Accept new connections.
 * @note you must call udps_init first.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
udps_err_t udps_accept(void);

/**
 * Close the UDP server.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
void udps_close(void);

#endif /* _UDP_SERVER_H_ */
