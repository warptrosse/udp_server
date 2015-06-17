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
 * @file udp_server.c
 */

#include "udp_server.h"
#include "udp_server_pool.h"
#include "udp_server_log.h"
#include "udp_server_cli.h"
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>


/********** SERVER INTERNAL DATA AND CONFIGURATIONS **********/

/**
 * UDP Server internal data.
 */
typedef struct udps_internal_data
{
    int              udpfd;    /**< UDP file descriptor. */
    ushort           port;     /**< Port number. */
    uchar            nclients; /**< Number of preforked clients. */
    pthread_mutex_t* mptr;     /**< Actual mutex will be in shared memory.
                                  This mutex is used as processes controller. */
    mqd_t            mqd;      /**< Message queue descriptor. We store incoming
                                  UDP datagrams here and child processes gather
                                  the datagrams. */
    uint             pUpdater; /**< 1=>Pool updater process, 0=>Otherwise.
                                  We set this variable in order to execute the
                                  server close rutine only once. */
} udps_internal_data_t;
static udps_internal_data_t srv;

/**
 * Maximum size for a UDP datagram message.
 */
#define UDPS_DATAGRAM_MSG_MAXLEN 2048

/**
 * Main loop. Where we listen for UDP datagrams.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_receive(void);


/********** MESSAGE QUEUE **********/

/**
 * Message queue name identifier.
 */
#define UDPS_MQ_NAME "/udps_mq"

/**
 * Maximum number of message on queue.
 * @note this value must be less or equals to the ceiling value defined
 *  by the OS (/proc/sys/fs/mqueue/msg_max). The limit is ignored for
 *  privileged processes (CAP_SYS_RESOURCE), but the HARD_MSGMAX ceiling
 *  is nevertheless imposed.
 */
#define UDPS_MQ_MAX_MSG 100

/**
 * Maximum message size (bytes).
 * Format: clientAddres|clientPort|msgLen|msg
 * Types : uint        |uint      |uint  |char*
 * @note this value must be less or equals to the ceiling value defined
 *  by the OS (/proc/sys/fs/mqueue/msgsize_max).  The limit is ignored for
 *  privileged processes (CAP_SYS_RESOURCE), but the HARD_MSGSIZEMAX ceiling
 *  is nevertheless imposed.
 */
#define UDPS_MQ_MSG_MAXLEN (sizeof(uint)+sizeof(uint)+sizeof(uint)+     \
                            UDPS_DATAGRAM_MSG_MAXLEN)

/**
 * Message queue message format.
 * Format: clientAddres|clientPort|msgLen|msg
 * Types : uint        |uint      |uint  |char*
 */
#define UDPS_MQ_MSG_FORMAT "%u|%u|%u|%s"

/**
 * Initialize the message queue.
 * We store incoming UDP datagrams here and child processes gather
 * the datagrams.
 */
static udps_err_t udps_mq_init(void);


/********** SHARED MEMORY (PROCESSES CONTROLLER) **********/

/**
 * Share memory object name.
 */
#define UDPS_SM_OBJ_NAME "/udps_sm_poll_controller"

/**
 * Initialize processes controller.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_lock_init(void);

/**
 * Lock processes controller.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_lock_wait(void);

/**
 * Unlock processes controller.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_lock_release(void);


/********** CLIENT **********/

/**
 * Client handler.
 */
static void udps_client_handler(void);

/**
 * Handle client signals.
 * @param[in] signo Signal number.
 */
static void udps_client_signal_handler(int signo);


/*----------------------------------------------------------------------------*/
udps_err_t udps_init(ushort port, uchar nclients)
{
    struct sockaddr_in srvaddr;
    socklen_t          srvlen;
    int                reuse;

    /* Setup internal configurations. */
    memset(&srv, 0, sizeof(srv));
    srv.port     = port;
    srv.nclients = nclients;

    /* Create UDP communication endpoint.
     * AF_INET     = Internet domain sockets.
     * SOCK_STREAM = Byte-stream socket. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Creating UDP socket..."));
    srv.udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(srv.udpfd < 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Unable to create UDP communication endpoint: "
                                 "%s (%d)", strerror(errno), errno));
        return UDPS_ERR_CREATE_UDP_SOCKET;
    }
    LOG_SRV(UDPS_LOG_DEBUG, ("UDP socket created: %d", srv.udpfd));

    /* Create server address.
     * INADDR_ANY = the socket will be bound to all local interfaces. */
    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family      = AF_INET;
    srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srvaddr.sin_port        = htons(srv.port);

    /* Allow reuse of local addresses.
     * SOL_SOCKET   = Manipulate the socket-level options.
     * SO_REUSEADDR = Indicates that the rules used in validating addresses
     *                supplied in a bind() call should allow reuse of local
     *                addresses. */
    reuse = 1;
    if(setsockopt(srv.udpfd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                  sizeof(reuse)) != 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Unable to set address as reusable: %s (%d)",
                                 strerror(errno), errno));
        return UDPS_ERR_SET_ADDR_REUSABLE;
    }

    /* Bind UDP endpoint to server address. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Binding UDP socket..."));
    if(bind(srv.udpfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) < 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Unable to bind server socket with its "
                                 "address: %s (%d)", strerror(errno), errno));
        udps_close();
        return UDPS_ERR_BIND_UDP_SOCKET;
    }

    /* Check sockname. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Checking sockname..."));
    srvlen = sizeof(srvaddr);
    if((getsockname(srv.udpfd, (struct sockaddr*)&srvaddr, &srvlen) < 0) ||
       (srvlen != sizeof(srvaddr))) {
        LOG_SRV(UDPS_LOG_EMERG, ("Invalid server socket address length: "
                                 "%u != %lu", srvlen, sizeof(srvaddr)));
        udps_close();
        return UDPS_ERR_INVALID_UDP_SOCKET;
    }

    /* Check address family. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Checking address family..."));
    if(srvaddr.sin_family != AF_INET) {
        LOG_SRV(UDPS_LOG_EMERG, ("Invalid server socket family: != AF_INET"));
        udps_close();
        return UDPS_ERR_INVALID_UDP_SOCKET;
    }

    /* Initialize. */
    LOG_SRV(UDPS_LOG_NOTICE, ("Init UDP => udpServer.udpfd: %d "
                              "- port: %u", srv.udpfd, srv.port));

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
udps_err_t udps_accept(void)
{
    pid_t      pid;
    udps_err_t rc;

    /* Initialize processes controller. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Initializing processes controller..."));
    rc = udps_lock_init();
    if(rc != UDPS_OK) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not initialize processes "
                                 "controller"));
        udps_close();
        return rc;
    }

    /* Initialize message queue. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Initializing message queue..."));
    rc = udps_mq_init();
    if(rc != UDPS_OK) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not initialize message queue"));
        udps_close();
        return rc;
    }

    /* Initialize processes pool. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Initializing processes pool..."));
    rc = udps_pool_init(srv.nclients, udps_client_handler);
    if(rc != UDPS_OK) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not initialize processes pool"));
        udps_close();
        return rc;
    }

    /* Launch Receiver and PoolUpdater processes. */
    pid = fork();
    if(pid > 0) { /* Parent. */
        srv.pUpdater = 0;
        rc = udps_receive();
    } else if(pid == 0) { /* Child. */
        srv.pUpdater = 1;
        for(;;) {
            sleep(1);
            rc = udps_pool_update();
            if(rc != UDPS_OK) {
                LOG_SRV(UDPS_LOG_ALERT, ("Unable to update processes pool"));
            }
        }
    } else {
        LOG_POOL(UDPS_LOG_CRIT, ("Unable to fork Receiver/PoolUpdater"
                                 "processes"));
        return UDPS_ERR_FORK;
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_receive(void)
{
    struct sockaddr_in cliaddr;
    socklen_t          clilen;
    socklen_t          stlen;
    char               msg[UDPS_DATAGRAM_MSG_MAXLEN];
    ssize_t            nread;
    char               mqmsg[UDPS_MQ_MSG_MAXLEN];
    size_t             mqmsglen;

    /* Main loop. */
    stlen = sizeof(cliaddr);
    for(;;) {
        /* Get new incoming UDP datagram. */
        clilen = stlen;
        nread  = recvfrom(srv.udpfd, msg, UDPS_DATAGRAM_MSG_MAXLEN, 0,
                          (struct sockaddr*)&cliaddr, &clilen);
        if(nread < 0) {
            continue;
        }

        /* Generate message queue message. */
        memset(mqmsg, 0, (sizeof(char)*UDPS_MQ_MSG_MAXLEN));
        snprintf(mqmsg, UDPS_MQ_MSG_MAXLEN, UDPS_MQ_MSG_FORMAT,
                 (uint)cliaddr.sin_addr.s_addr, (uint)cliaddr.sin_port,
                 (uint)nread, msg);
        mqmsglen = strnlen(mqmsg, UDPS_MQ_MSG_MAXLEN);
        LOG_SRV(UDPS_LOG_NOTICE, ("UDP datagram received: %s (%d)",
                                  mqmsg, (uint)mqmsglen));

        /* Enqueue message. */
        if(mq_send(srv.mqd, mqmsg, mqmsglen, 0) != 0) {
            LOG_SRV(UDPS_LOG_ALERT, ("Could not enqueue message: %s (%d)",
                                     strerror(errno), errno));
        }
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
void udps_close(void)
{
    int rc;

    /* Check whether we are in the pool updater process. */
    if(srv.pUpdater == 1) {
        return;
    }

    /* Close UDP socket. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Closing UDP socket..."));
    if(close(srv.udpfd) != 0) {
        LOG_SRV(UDPS_LOG_WARNING, ("Unable to close UDP socket: %s (%d)",
                                   strerror(errno), errno));
    }

    /* Close processes pool. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Closing processes pool..."));
    if(udps_pool_close() != UDPS_OK) {
        LOG_SRV(UDPS_LOG_WARNING, ("Unable to close processes pool"));
    }

    /* Wait for children to be destroyed. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Waiting for children to be destroyed..."));
    do {
        rc = wait(NULL);
        if((rc == -1) && (errno != ECHILD)) {
            LOG_SRV(UDPS_LOG_WARNING, ("Waiting children to be destroyed "
                                       "error: %s (%d)",
                                       strerror(errno), errno));
        }
    } while(rc > 0);

    /* Close message queue. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Closing message queue..."));
    rc = mq_close(srv.mqd);
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_WARNING, ("Unable to close message queue: %s (%d)",
                                   strerror(errno), errno));
    }
    rc = mq_unlink(UDPS_MQ_NAME);
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_WARNING, ("Unable to unlink message queue: %s (%d)",
                                   strerror(errno), errno));
    }

    /* Close processes controller. */
    if(srv.mptr != NULL) {
        LOG_SRV(UDPS_LOG_DEBUG, ("Closing processes controller..."));
        rc = pthread_mutex_destroy(srv.mptr);
        if(rc != 0) {
            LOG_SRV(UDPS_LOG_WARNING, ("Unable to destroy pthread mutex: %d",
                                       rc));
        }
        rc = munmap(srv.mptr, sizeof(pthread_mutex_t));
        if(rc != 0) {
            LOG_SRV(UDPS_LOG_WARNING, ("Unable to destroy share memory "
                                       "mapping: %s (%d)",
                                       strerror(errno), errno));
        }
        rc = shm_unlink(UDPS_SM_OBJ_NAME);
        if(rc != 0) {
            LOG_SRV(UDPS_LOG_WARNING, ("Unable to unlink share memory object: "
                                       "%d", rc));
        }
    }

    /* Secure clean. */
    memset(&srv, 0, sizeof(srv));
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_mq_init(void)
{
    struct mq_attr attr;

    /* If the message queue already exists, unlink it. */
    shm_unlink(UDPS_MQ_NAME);

    /* Setup message queue attributes. */
    memset(&attr, 0, sizeof(attr));
    attr.mq_maxmsg  = UDPS_MQ_MAX_MSG;
    attr.mq_msgsize = UDPS_MQ_MSG_MAXLEN;
    LOG_SRV(UDPS_LOG_DEBUG, ("Message queue configuration: maxmsg=%ld ; "
                             "msgsize=%ld", attr.mq_maxmsg, attr.mq_msgsize));

    /* Create a new message queue.
     * O_RDWR  = Open for reading and writing.
     * O_CREAT = Create the message queue if it does not exist.
     * O_EXCL  = If the given name already exists, return an error.
     * S_IRUSR = User has read permission.
     * S_IWUSR = User has write permission. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Creating message queue..."));
    srv.mqd = mq_open(UDPS_MQ_NAME, (O_RDWR|O_CREAT|O_EXCL),
                      (S_IRUSR|S_IWUSR), &attr);
    if(srv.mqd == (mqd_t)-1) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not create message queue: %s (%d)",
                                 strerror(errno), errno));
        return UDPS_ERR_MQ_CREATE;
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_lock_init(void)
{
    int                 smfd;
    pthread_mutexattr_t mattr;
    int                 rc;

    /* If the shared memory object already exists, unlink it. */
    shm_unlink(UDPS_SM_OBJ_NAME);

    /* Create a new share memory object.
     * O_RDWR  = Open for reading and writing.
     * O_CREAT = Create the shared memory object if it does not exist.
     * O_EXCL  = If the given name already exists, return an error.
     * S_IRUSR = User has read permission.
     * S_IWUSR = User has write permission. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Creating shared memory object..."));
    smfd = shm_open(UDPS_SM_OBJ_NAME, (O_RDWR|O_CREAT|O_EXCL|O_TRUNC),
                    (S_IRUSR|S_IWUSR));
    if(smfd < 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not create share memory object: "
                                 "%s (%d)", strerror(errno), errno));
        return UDPS_ERR_SMEM_OBJ_CREATE;
    }
    rc = ftruncate(smfd, sizeof(pthread_mutex_t));
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not truncate share memory object: "
                                 "%s (%d)", strerror(errno), errno));
        return UDPS_ERR_SMEM_OBJ_TRUNC;
    }

    /* Create a new mapping in the virtual address space.
     * NULL       = The kernel chooses the address at which to create the
     *              mapping.
     * PROT_READ  = Pages may be read.
     * PROT_WRITE = Pages may be written.
     * MAP_SHARED = Updates to the mapping are visible to other processes
     *              that map this file. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Creating shared memory mapping..."));
    srv.mptr = (pthread_mutex_t*)mmap(NULL, sizeof(pthread_mutex_t),
                                      (PROT_READ|PROT_WRITE), MAP_SHARED,
                                      smfd, 0);
    if(srv.mptr == MAP_FAILED) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not create share memory mapping: "
                                 "%s (%d)", strerror(errno), errno));
        close(smfd);
        return UDPS_ERR_SMEM_MAP_CREATE;
    }

    /* Close shared memory object. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Closing shared memory object..."));
    if(close(smfd) != 0) {
        LOG_SRV(UDPS_LOG_WARNING, ("Could not close shared memory object: "
                                   "%s (%d)", strerror(errno), errno));
    }

    /* Create processes controller mutex.
     * PTHREAD_PROCESS_SHARED = permit a mutex to be operated upon by any thread
     *                          that has access to the memory where the mutex is
     *                          allocated, even if the mutex is allocated in
     *                          memory that is shared by multiple processes.
     * PTHREAD_MUTEX_ROBUST   = If the process containing the owning thread of a
     *                          robust mutex terminates while holding the mutex
     *                          lock, the next thread that acquires the mutex
     *                          shall be notified about the termination by the
     *                          return value [EOWNERDEAD] from the locking
     *                          function. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Creating processes controler mutex..."));
    rc = pthread_mutexattr_init(&mattr);
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not create pthread mutex attribute: "
                                 "%d", rc));
        return UDPS_ERR_SMEM_ATTR_CREATE;
    }
    rc = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not set pthread mutex attribute as "
                                 "shared: %d", rc));
        pthread_mutexattr_destroy(&mattr);
        return UDPS_ERR_SMEM_ATTR_SET;
    }
    rc = pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not set pthread mutex attribute as "
                                 "robust: %d", rc));
        pthread_mutexattr_destroy(&mattr);
        return UDPS_ERR_SMEM_ATTR_SET;
    }
    rc = pthread_mutex_init(srv.mptr, &mattr);
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not initialize pthread mutex: %d",
                                 rc));
        pthread_mutexattr_destroy(&mattr);
        return UDPS_ERR_SMEM_MUTEX_INIT;
    }

    /* Close unneeded pthread mutex attribute. */
    LOG_SRV(UDPS_LOG_DEBUG, ("Destroying unneeded pthread mutex attribute..."));
    rc = pthread_mutexattr_destroy(&mattr);
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_WARNING, ("Could not close pthread mutex attribute: "
                                   "%d", rc));
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_lock_wait(void)
{
    int rc;

    /* Lock processes controller mutex. */
    rc = pthread_mutex_lock(srv.mptr);
    if(rc == EOWNERDEAD) {
        /* Owner of the robust mutex terminated while holding the mutex.
         * Marking it as consistent again. */
        rc = pthread_mutex_consistent(srv.mptr);
        if(rc != 0) {
            LOG_SRV(UDPS_LOG_ALERT, ("Could not recovery mutex: %d", rc));
            return UDPS_ERR_SMEM_MUTEX_LOCK;
        }
    } else if(rc == ENOTRECOVERABLE) {
        LOG_SRV(UDPS_LOG_ALERT, ("Mutex not recoverable: %d", rc));
        return UDPS_ERR_SMEM_MUTEX_LOCK;
    } else if(rc != 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not lock processes controller mutex: "
                                 "%d", rc));
        return UDPS_ERR_SMEM_MUTEX_LOCK;
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_lock_release(void)
{
    int rc;

    /* Unlock processes controller mutex. */
    rc = pthread_mutex_unlock(srv.mptr);
    if(rc != 0) {
        LOG_SRV(UDPS_LOG_EMERG, ("Could not unlock processes controller mutex: "
                                 "%d", rc));
        return UDPS_ERR_SMEM_MUTEX_UNLOCK;
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static void udps_client_handler(void)
{
    char    mqmsg[UDPS_MQ_MSG_MAXLEN];
    ssize_t nread;
    uint    cliAddr;
    uint    cliPort;
    uint    cliMsgLen;
    char    cliMsg[UDPS_DATAGRAM_MSG_MAXLEN];

    /* Set signal handlers.
     * SIGINT  = When the user types the INTR character (normally C-c).
     * SIGTERM = Generic signal used to cause program termination. */
    signal(SIGINT, NULL);
    signal(SIGUSR1, udps_client_signal_handler);
    signal(SIGTERM, udps_client_signal_handler);

    /* Handle new connections. */
    for(;;) {
        /* Waiting for new requests. */
        LOG_SRV(UDPS_LOG_NOTICE, ("Waiting for client request..."));
        udps_pool_set_process_status(getpid(), udps_pool_proc_status_idle);
        udps_lock_wait();
        nread = mq_receive(srv.mqd, mqmsg, UDPS_MQ_MSG_MAXLEN, NULL);
        if(nread < 0) {
            LOG_SRV(UDPS_LOG_ERR, ("Unable to gather message from message "
                                   "queue: %s (%d)", strerror(errno), errno));
            udps_lock_release();
            continue;
        }
        udps_lock_release();
        udps_pool_set_process_status(getpid(), udps_pool_proc_status_working);
        LOG_SRV(UDPS_LOG_NOTICE, ("Processing request: %s (%d)",
                                  mqmsg, (uint)nread));

        /* Process request. */
        sscanf(mqmsg, UDPS_MQ_MSG_FORMAT, &cliAddr, &cliPort, &cliMsgLen, cliMsg);
        if(udps_client_process_request(cliAddr, cliPort,
                                       cliMsg, cliMsgLen) != UDPS_OK) {
            LOG_SRV(UDPS_LOG_ERR, ("Could not process client request"));
        }
    }
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static void udps_client_signal_handler(int signo)
{
    (void)signo;
    LOG_SRV(UDPS_LOG_NOTICE, ("Signal received: %s (%d). Closing UDP client",
                              strsignal(signo), signo));

    /* Update pool. */
    if(signo == SIGTERM) {
        udps_pool_set_process_status(getpid(), udps_pool_proc_status_ninit);
    }

    /* Close message queue. */
    if(mq_close(srv.mqd) != 0) {
        LOG_SRV(UDPS_LOG_WARNING, ("Unable to close message queue: %s (%d)",
                                   strerror(errno), errno));
    }

    /* Exit. */
    exit(EXIT_SUCCESS);
}
/*----------------------------------------------------------------------------*/
