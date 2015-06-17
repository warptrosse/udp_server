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
 * @file main.c
 */

#include "udp_server.h"
#include "udp_server_log.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>

static void udps_signal_handler(int signo);
static void udps_print_usage(const char* progname);

/*----------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    ushort     port;
    uchar      nclients;
    udps_err_t rc;

    /* Check server initialization arguments. */
    if(argc != 3) {
        udps_print_usage(argv[0]);
    }

    /* Load configuration. */
    port     = atoi(argv[1]);
    nclients = atoi(argv[2]);

    /* Handle signals.
     * SIGINT  = When the user types the INTR character (normally C-c).
     * SIGTERM = Generic signal used to cause program termination. */
    signal(SIGINT, udps_signal_handler);
    signal(SIGTERM, NULL);

    /* Initialize. */
    rc = udps_init(port, nclients);
    if(rc != UDPS_OK) {
        LOG_MAIN(UDPS_LOG_EMERG, ("Unable to initialize  UDP server"));
        exit(EXIT_FAILURE);
    }

    /* Accept. */
    rc = udps_accept();
    if(rc != UDPS_OK) {
        LOG_MAIN(UDPS_LOG_EMERG, ("Unable to start accepting"));
        exit(EXIT_FAILURE);
    }

    /* Close. */
    udps_close();

    return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/**
 * Handle SIGINT signal.
 * @param[in] signo
 */
static void udps_signal_handler(int signo)
{
    (void)signo;
    LOG_MAIN(UDPS_LOG_NOTICE, ("Signal received: %s (%d). Closing UDP server",
                               strsignal(signo), signo));
    udps_close();
    exit(EXIT_SUCCESS);
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/**
 * Prints udp Server command usage.
 * @param[in] progname Program name.
 */
static void udps_print_usage(const char* progname)
{
    (void)fprintf(stderr, "usage: %s <port_number> <num_clients>\n", progname);
    exit(EXIT_FAILURE);
}
/*----------------------------------------------------------------------------*/
