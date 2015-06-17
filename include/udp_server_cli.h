#ifndef _UDP_SERVER_CLI_H_
#define _UDP_SERVER_CLI_H_

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
 * @file udp_server_cli.h
 */

#include "udp_server_err.h"
#include "udp_server_types.h"

/**
 * Process client requests.
 * @param cliAddr [in] Client address (in network byte order).
 * @param cliPort [in] Client port (in network byte order).
 * @param cliMsg [in] Client request message.
 * @param cliMsgLen [in] Client request message length.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
udps_err_t udps_client_process_request(uint cliAddr, uint cliPort,
                                       const char* const cliMsg,
                                       uint cliMsgLen);

#endif /* _UDP_SERVER_CLI_H_ */
