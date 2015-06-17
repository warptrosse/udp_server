#ifndef _UDP_SERVER_LOG_H_
#define _UDP_SERVER_LOG_H_

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
 * @file udp_server_log.h
 */

#include "udp_server_types.h"
#include <stdio.h>
#include <unistd.h>
#include <time.h>

/**
 * Enable log system.
 */
#define UDPS_LOG_ENABLE

/**
 * Enable modules log.
 */
#ifdef UDPS_LOG_ENABLE
#define UDPS_LOG_MOD_MAIN_ENABLE
#define UDPS_LOG_MOD_SRV_ENABLE
#define UDPS_LOG_MOD_POOL_ENABLE
#endif /* UDPS_LOG_ENABLE */

/**
 * Log levels.
 */
#define UDPS_LOG_EMERG   (1<<0) /* System is unusable. */
#define UDPS_LOG_ALERT   (1<<1) /* Action must be taken immediately. */
#define UDPS_LOG_CRIT    (1<<2) /* Critical conditions. */
#define UDPS_LOG_ERR     (1<<3) /* Error conditions. */
#define UDPS_LOG_WARNING (1<<4) /* Warning conditions. */
#define UDPS_LOG_NOTICE  (1<<5) /* Normal, but significant, condition. */
#define UDPS_LOG_INFO    (1<<6) /* Informational message. */
#define UDPS_LOG_DEBUG   (1<<7) /* Debug-level message. */

/**
 * Current log level.
 */
#define UDPS_LOG_LVL                            \
    UDPS_LOG_EMERG   |                          \
    UDPS_LOG_ALERT   |                          \
    UDPS_LOG_CRIT    |                          \
    UDPS_LOG_ERR     |                          \
    UDPS_LOG_WARNING |                          \
    UDPS_LOG_NOTICE  |                          \
    UDPS_LOG_INFO

/**
 * Log message helpers.
 * @param[in] lvl Level.
 * @param[in] msg Message.
 */
#ifdef UDPS_LOG_MOD_MAIN_ENABLE
#define LOG_MAIN(lvl, msg) {                                    \
        if(lvl&(UDPS_LOG_LVL)) {                                \
            printf("%u|%d|", (uint)time(NULL), getpid());       \
            printf msg; printf("\n");                           \
        }                                                       \
    }
#else /* UDPS_LOG_MOD_MAIN_ENABLE */
#define LOG_MAIN(lvl, msg)
#endif /* UDPS_LOG_MOD_MAIN_ENABLE */

#ifdef UDPS_LOG_MOD_SRV_ENABLE
#define LOG_SRV(lvl, msg) {                                     \
        if(lvl&(UDPS_LOG_LVL)) {                                \
            printf("%u|%d|", (uint)time(NULL), getpid());       \
            printf msg; printf("\n");                           \
        }                                                       \
    }
#else /* UDPS_LOG_MOD_SRV_ENABLE */
#define LOG_SRV(lvl, msg)
#endif /* UDPS_LOG_MOD_SRV_ENABLE */

#ifdef UDPS_LOG_MOD_POOL_ENABLE
#define LOG_POOL(lvl, msg) {                                    \
        if(lvl&(UDPS_LOG_LVL)) {                                \
            printf("%u|%d|", (uint)time(NULL), getpid());       \
            printf msg; printf("\n");                           \
        }                                                       \
    }
#else /* UDPS_LOG_MOD_POOL_ENABLE */
#define LOG_POOL(lvl, msg)
#endif /* UDPS_LOG_MOD_POOL_ENABLE */

#endif /* _UDP_SERVER_LOG_H_ */
