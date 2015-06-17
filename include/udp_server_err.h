#ifndef _UDP_SERVER_ERR_H_
#define _UDP_SERVER_ERR_H_

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
 * @file udp_server_err.h
 */

/**
 * Error codes.
 */
typedef enum udps_err {
    UDPS_OK,                          /**< Operation executed successfully. */
    UDPS_ERR_RECV_PARAMS,             /**< Invalid received parameters in a
                                         function. */
    UDPS_ERR_NO_MEMORY,               /**< No memory available. */
    UDPS_ERR_GET_RLIMIT,              /**< Could not get RLIMIT resource. */
    UDPS_ERR_SET_RLIMIT,              /**< Could not set RLIMIT resource. */
    UDPS_ERR_CREATE_UDP_SOCKET,       /**< An error occurred while trying to
                                         create the UDP socket. */
    UDPS_ERR_SET_ADDR_REUSABLE,       /**< Unable to set address as reusable. */
    UDPS_ERR_BIND_UDP_SOCKET,         /**< Could not bind the UDP socket to
                                         address structure. */
    UDPS_ERR_INVALID_UDP_SOCKET,      /**< Invalid UDP socket.*/
    UDPS_ERR_MQ_CREATE,               /**< Could not create message queue. */
    UDPS_ERR_SMEM_OBJ_CREATE,         /**< Could not create share memory
                                         object. */
    UDPS_ERR_SMEM_OBJ_TRUNC,          /**< Could not truncate share memory
                                         object. */
    UDPS_ERR_SMEM_MAP_CREATE,         /**< Could not create share memory
                                         mapping. */
    UDPS_ERR_SMEM_ATTR_CREATE,        /**< Could not create pthread mutex
                                         attribute. */
    UDPS_ERR_SMEM_ATTR_SET,           /**< Could not set pthread mutex
                                         attribute as shared. */
    UDPS_ERR_SMEM_MUTEX_INIT,         /**< Could not initialize pthread
                                         mutex. */
    UDPS_ERR_SMEM_MUTEX_LOCK,         /**< Could not lock processes controller
                                         mutex. */
    UDPS_ERR_SMEM_MUTEX_UNLOCK,       /**< Could not unlock processes controller
                                         mutex. */
    UDPS_ERR_FORK,                    /**< Could not fork Receiver/PoolUpdater
                                         processes. */
    UDPS_ERR_CLIENT_REQ_READ,         /**< Could not read request. */
    UDPS_ERR_CLIENT_RESP_WRITE,       /**< Could not write response. */
    UDPS_ERR_POOL_PFF_INVALID,        /**< Invalid received prefork function. */
    UDPS_ERR_POOL_NUMPFC_INVALID,     /**< Invalid received number of preforked
                                         processes. */
    UDPS_ERR_POOL_SMEM_OBJ_CREATE,    /**< Could not create shared memory
                                         object. */
    UDPS_ERR_POOL_SMEM_OBJ_TRUNC,     /**< Could not truncate share memory
                                         object. */
    UDPS_ERR_POOL_SMEM_MAP_CREATE,    /**< Could not create share memory
                                         mapping. */
    UDPS_ERR_POOL_SMEM_ATTR_CREATE,   /**< Could not create pthread rwlock
                                         attribute. */
    UDPS_ERR_POOL_SMEM_ATTR_SET,      /**< Could not set pthread rwlock
                                         attribute as shared. */
    UDPS_ERR_POOL_SMEM_RWLOCK_INIT,   /**< Could not initialize pthread
                                         rwlock. */
    UDPS_ERR_POOL_SMEM_RWLOCK_LOCK,   /**< Could not lock processes controller
                                         rwlock. */
    UDPS_ERR_POOL_SMEM_RWLOCK_UNLOCK, /**< Could not unlock processes controller
                                         rwlock. */
    UDPS_ERR_POOL_FULL,               /**< Fork is not allow. Pool is currently
                                         full. */
    UDPS_ERR_POOL_MIN,                /**< Kill is not allow. Pool is currently
                                         at minimum. */
    UDPS_ERR_POOL_FULL_INIT,          /**< Could not get an uninitialized
                                         process. Full initialized. */
    UDPS_ERR_POOL_FORK_FAIL,          /**< Unable to fork process. */
    UDPS_ERR_POOL_ALL_WORK,           /**< Could not get an idle process.
                                         All working. */
    UDPS_ERR_POOL_KILL_FAIL,          /**< Could not kill process. */
    UDPS_ERR_POOL_NINIT_NOT_FOUND,    /**< Unable to find an uninitialized
                                         process. */
    UDPS_ERR_POOL_ALREADY_INIT,       /**< Pool already initialized. */
    UDPS_ERR_POOL_NOT_INIT,           /**< Pool not initialized. */
    UDPS_UNK                          /**< An unknown error has occurred. */
} udps_err_t;

#endif /* _UDP_SERVER_ERR_H_ */
