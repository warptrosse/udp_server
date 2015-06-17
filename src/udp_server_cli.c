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
 * @file udp_server_cli.c
 */

#include "udp_server_cli.h"
#include "udp_server_log.h"
#include <arpa/inet.h>

/*----------------------------------------------------------------------------*/
udps_err_t udps_client_process_request(uint cliAddr, uint cliPort,
                                       const char* const cliMsg,
                                       uint cliMsgLen)
{
    struct in_addr addr;

    /* Request received. */
    addr.s_addr = cliAddr;
    LOG_SRV(UDPS_LOG_NOTICE, ("Request received: addr=%s ; port=%u ; "
                              "msg=%s (%u)", inet_ntoa(addr), cliPort,
                              cliMsg, cliMsgLen));
    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/
