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
 * @file udp_server_pool.c
 */

#include "udp_server_pool.h"
#include "udp_server_log.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>


/********** SERVER POOL INTERNAL DATA AND CONFIGURATIONS **********/

/**
 * Maximum number of clients forked allowed.
 */
#define UDPS_POOL_CLIENTS_MAX 100

/**
 * Minimum number of clients forked allowed.
 */
#define UDPS_POOL_CLIENTS_MIN 5

/**
 * This macro establishes the delta used to determine whether we should
 * fork more processes (to be prepared to handle possible incoming requests)
 * or kill idle (useless) processes.
 * ((current_idle_processes) <= delta) fork more processes.
 * ((current_idle_processes) > 3*delta) kill processes.
 */
#define UDPS_POOL_CLIENTS_CONTROL_DELTA 5

/**
 * Client process data.
 */
typedef struct udps_pool_cli
{
    pid_t                   pid;    /**< Process identifier. */
    udps_pool_proc_status_t status; /**< Process status. */
} udps_pool_cli_t;

/**
 * UDP Server pool data.
 */
typedef struct udps_pool
{
    uchar            anum;   /**< Number of currently preforked processes. */
    uchar            inum;   /**< Number of idle processes in the pool. */
    uchar            wnum;   /**< Number of working processes in the pool. */
    udps_pool_cli_t  procs[UDPS_POOL_CLIENTS_MAX]; /**< Pool processes. */
    pthread_rwlock_t rwlock; /**< This rwlock object is used control the pool
                                status. */
} udps_pool_t;
static udps_pool_t* pool;

/**
 * Indicates current pool status.
 * 0=>not initialized | 1=>initialized | 2=>closing.
 */
static uchar udps_pool_status = 0;


/********** SHARED MEMORY **********/

/**
 * Share memory object name.
 */
#define UDPS_POOL_SM_OBJ_NAME "/udps_sm_pool_data"

/**
 * Initialize pool controller.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_pool_lock_init(void);

/**
 * Lock pool controller (for reading).
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_pool_lock_wait_read(void);

/**
 * Lock pool controller (for writting).
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_pool_lock_wait_write(void);

/**
 * Unlock pool controller.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_pool_lock_release(void);


/********** PROCESSES POOL **********/

/**
 * The function to be called after a fork.
 */
udps_post_fork_fnc_t udps_pool_pff;

/**
 * Fork a new process and add it to the pool.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_pool_fork(void);

/**
 * Kill an unneeded process and remove it from the pool.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_pool_kill(void);

/**
 * Get the first process with the specified status.
 * @param[in] pstatus Process status.
 * @param[out] pnum First process at udps_pool_proc_status_ninit status.
 * @return UDPS_OK=>success | UDPS_*=>other status.
 */
static udps_err_t udps_pool_get_pnum(udps_pool_proc_status_t pstatus,
                                     uchar* pnum);

/**
 * Update pool statistics.
 * @param[in] prev_status Process previous status.
 * @param[in] new_status Process new status.
 */
static void udps_pool_update_stats(udps_pool_proc_status_t prev_status,
                                   udps_pool_proc_status_t new_status);


/*----------------------------------------------------------------------------*/
udps_err_t udps_pool_init(uchar numpfc, udps_post_fork_fnc_t pff)
{
    udps_err_t rc;
    uint       i;

    /* Check received parameters. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Checking received parameters..."));
    if(pff == NULL) {
        LOG_POOL(UDPS_LOG_EMERG, ("Invalid received post fork function: "
                                  "NULL"));
        return UDPS_ERR_POOL_PFF_INVALID;
    }
    if((numpfc > UDPS_POOL_CLIENTS_MAX) || (numpfc < UDPS_POOL_CLIENTS_MIN)) {
        LOG_POOL(UDPS_LOG_EMERG, ("Invalid received number of preforked "
                                  "processes: %u", numpfc));
        return UDPS_ERR_POOL_NUMPFC_INVALID;
    }

    /* Check pool status. */
    if(udps_pool_status > 0) {
        LOG_POOL(UDPS_LOG_CRIT, ("Pool already initialized"));
        return UDPS_ERR_POOL_ALREADY_INIT;
    }

    /* Initialize pool status. */
    udps_pool_status = 0;

    /* Initialize pool controller. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Initializing pool controller..."));
    rc = udps_pool_lock_init();
    if(rc != UDPS_OK) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not initialize pool controller"));
        return rc;
    }

    /* Setup pool. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Setting up pool..."));
    udps_pool_pff = pff;
    for(i=0 ; i<UDPS_POOL_CLIENTS_MAX ; ++i) {
        pool->procs[i].status = udps_pool_proc_status_ninit;
        pool->procs[i].pid    = 0;
    }

    /* Prefork processes. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Preforking %u processes...", numpfc));
    for(i=0 ; i<numpfc ; ++i) {
        if(udps_pool_fork() != UDPS_OK) {
            LOG_POOL(UDPS_LOG_CRIT, ("Unable to fork process"));
        }
    }
    udps_pool_status = 1;

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
udps_err_t udps_pool_update(void)
{
    uint i;
    uint tofork;
    uint tokill;

    /* Check pool status. */
    if(udps_pool_status != 1) {
        return UDPS_OK;
    }

    /* Pool update. */
    tofork = 0;
    tokill = 0;
    udps_pool_lock_wait_read();
    LOG_POOL(UDPS_LOG_INFO, ("POOL STATS: idle_num=%u ; working_num=%u ; "
                             "active_num=%u",
                             pool->inum, pool->wnum, pool->anum));

    /* Do we need to add processes?. */
    if(pool->inum <= UDPS_POOL_CLIENTS_CONTROL_DELTA) {
        tofork = (UDPS_POOL_CLIENTS_CONTROL_DELTA-pool->inum);

        /* Do we need to kill processes?. */
    } else if(pool->inum > (3*UDPS_POOL_CLIENTS_CONTROL_DELTA)) {
        tokill = (pool->inum-(3*UDPS_POOL_CLIENTS_CONTROL_DELTA));
    }
    udps_pool_lock_release();

    /* Fork new processes if necesary. */
    for(i=0 ; i<tofork ; ++i) {
        if(udps_pool_fork() != UDPS_OK) {
            LOG_POOL(UDPS_LOG_CRIT, ("Unable to fork process"));
        }
    }

    /* Kill processes if necesary. */
    for(i=0 ; i<tokill ; ++i) {
        if(udps_pool_kill() != UDPS_OK) {
            LOG_POOL(UDPS_LOG_WARNING, ("Unable to kill process"));
        }
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
udps_err_t udps_pool_close(void)
{
    uint i;
    uint rc;

    /* Check pool status. */
    if(udps_pool_status != 1) {
        LOG_POOL(UDPS_LOG_CRIT, ("Pool not initialized"));
        return UDPS_ERR_POOL_NOT_INIT;
    }
    udps_pool_status = 2;

    /* Close processes. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Closing processes..."));
    udps_pool_lock_wait_write();
    for(i=0 ; i<UDPS_POOL_CLIENTS_MAX ; ++i) {
        if(pool->procs[i].status == udps_pool_proc_status_ninit) {
            continue;
        }
        if(kill(pool->procs[i].pid, SIGUSR1) != 0) {
            LOG_POOL(UDPS_LOG_CRIT, ("Could not kill process %u: pid=%d ; "
                                     "%s (%d)", i, pool->procs[i].pid,
                                     strerror(errno), errno));
            continue;
        }
        udps_pool_update_stats(pool->procs[i].status,
                               udps_pool_proc_status_ninit);
        LOG_POOL(UDPS_LOG_NOTICE, ("Process %u killed: pid=%d",
                                   i, pool->procs[i].pid));
        pool->procs[i].pid    = 0;
        pool->procs[i].status = udps_pool_proc_status_ninit;
    }
    LOG_POOL(UDPS_LOG_NOTICE, ("Remaining processes after pool closed: %u",
                               pool->anum));
    udps_pool_lock_release();

    /* Close pool controller. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Closing processes controller..."));
    rc = pthread_rwlock_destroy(&pool->rwlock);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_WARNING, ("Unable to destroy pthread rwlock: %d",
                                    rc));
    }
    rc = munmap(pool, sizeof(udps_pool_t));
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_WARNING, ("Unable to destroy share memory "
                                    "mapping: %s (%d)", strerror(errno),
                                    errno));
    }
    rc = shm_unlink(UDPS_POOL_SM_OBJ_NAME);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_WARNING, ("Unable to unlink share memory object: "
                                    "%d", rc));
    }

    /* Secure clean. */
    pool          = NULL;
    udps_pool_pff = NULL;

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_pool_lock_init(void)
{
    int                  smfd;
    pthread_rwlockattr_t rwattr;
    int                  rc;

    /* If the shared memory object already exists, unlink it. */
    shm_unlink(UDPS_POOL_SM_OBJ_NAME);

    /* Create a new share memory object.
     * O_RDWR  = Open for reading and writing.
     * O_CREAT = Create the shared memory object if it does not exist.
     * O_EXCL  = If the given name already exists, return an error.
     * S_IRUSR = User has read permission.
     * S_IWUSR = User has write permission. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Creating shared memory object..."));
    smfd = shm_open(UDPS_POOL_SM_OBJ_NAME, (O_RDWR|O_CREAT|O_EXCL),
                    (S_IRUSR|S_IWUSR));
    if(smfd < 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not create share memory object: "
                                  "%s (%d)", strerror(errno), errno));
        return UDPS_ERR_POOL_SMEM_OBJ_CREATE;
    }
    rc = ftruncate(smfd, sizeof(udps_pool_t));
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not truncate share memory object: "
                                  "%s (%d)", strerror(errno), errno));
        return UDPS_ERR_POOL_SMEM_OBJ_TRUNC;
    }

    /* Create a new mapping in the virtual address space.
     * NULL       = The kernel chooses the address at which to create the
     *              mapping.
     * PROT_READ  = Pages may be read.
     * PROT_WRITE = Pages may be written.
     * MAP_SHARED = Updates to the mapping are visible to other processes
     *              that map this file. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Creating shared memory mapping..."));
    pool = (udps_pool_t*)mmap(NULL, sizeof(udps_pool_t),
                              (PROT_READ|PROT_WRITE), MAP_SHARED, smfd, 0);
    if(pool == MAP_FAILED) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not create share memory mapping: "
                                  "%s (%d)", strerror(errno), errno));
        close(smfd);
        return UDPS_ERR_POOL_SMEM_MAP_CREATE;
    }

    /* Close shared memory object. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Closing shared memory object..."));
    if(close(smfd) != 0) {
        LOG_POOL(UDPS_LOG_WARNING, ("Could not close shared memory object: "
                                    "%s (%d)", strerror(errno), errno));
    }

    /* Create pool controller rwlock.
     * PTHREAD_PROCESS_SHARED = permit a read-write lock to be operated upon by
     *                          any thread that has access to the memory where
     *                          the read-write lock is allocated, even if the
     *                          read-write lock is allocated in memory that is
     *                          shared by multiple processes. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Creating pool controler rwlock..."));
    rc = pthread_rwlockattr_init(&rwattr);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not create pthread rwlock attribute: "
                                  "%d", rc));
        return UDPS_ERR_POOL_SMEM_ATTR_CREATE;
    }
    rc = pthread_rwlockattr_setpshared(&rwattr, PTHREAD_PROCESS_SHARED);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not set pthread rwlock attribute as "
                                  "shared: %d", rc));
        pthread_rwlockattr_destroy(&rwattr);
        return UDPS_ERR_POOL_SMEM_ATTR_SET;
    }
    rc = pthread_rwlock_init(&pool->rwlock, &rwattr);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not initialize pthread rwlock: %d",
                                  rc));
        pthread_rwlockattr_destroy(&rwattr);
        return UDPS_ERR_POOL_SMEM_RWLOCK_INIT;
    }

    /* Close unneeded pthread rwlock attribute. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Destroying unneeded pthread rwlock "
                              "attribute..."));
    rc = pthread_rwlockattr_destroy(&rwattr);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_WARNING, ("Could not close pthread rwlock attribute: "
                                    "%d", rc));
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_pool_lock_wait_read(void)
{
    int rc;

    /* Lock pool controller rwlock. */
    rc = pthread_rwlock_rdlock(&pool->rwlock);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not lock pool controller rwlock "
                                  "(read): %d", rc));
        return UDPS_ERR_POOL_SMEM_RWLOCK_LOCK;
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_pool_lock_wait_write(void)
{
    int rc;

    /* Lock pool controller rwlock. */
    rc = pthread_rwlock_wrlock(&pool->rwlock);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not lock pool controller rwlock "
                                  "(write): %d", rc));
        return UDPS_ERR_POOL_SMEM_RWLOCK_LOCK;
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_pool_lock_release(void)
{
    int rc;

    /* Unlock pool controller rwlock. */
    rc = pthread_rwlock_unlock(&pool->rwlock);
    if(rc != 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Could not unlock pool controller rwlock: "
                                  "%d", rc));
        return UDPS_ERR_POOL_SMEM_RWLOCK_UNLOCK;
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_pool_fork(void)
{
    pid_t      pid;
    uchar      n;
    udps_err_t rc;

    LOG_POOL(UDPS_LOG_DEBUG, ("Trying to fork a new process..."));

    /* The current number of active processes in the pool must not be higher
     * than UDPS_POOL_CLIENTS_MAX. */
    udps_pool_lock_wait_read();
    assert((pool->anum <= UDPS_POOL_CLIENTS_MAX));

    /* If the pool is full, skip. */
    if(pool->anum == UDPS_POOL_CLIENTS_MAX) {
        LOG_POOL(UDPS_LOG_WARNING, ("Fork is not allow. Pool is currently "
                                    "full: %u", pool->anum));
        return UDPS_ERR_POOL_FULL;
    }
    udps_pool_lock_release();

    /* Get first uninitialized process. */
    rc = udps_pool_get_pnum(udps_pool_proc_status_ninit, &n);
    if(rc != UDPS_OK) {
        LOG_POOL(UDPS_LOG_WARNING, ("Could not get an uninitialized process. "
                                    "All processes allowed were initialized"));
        return UDPS_ERR_POOL_FULL_INIT;
    }

    /* Fork a new process. */
    pid = fork();
    if(pid > 0) { /* Parent. */
        /* Updating pool data. */
        udps_pool_lock_wait_write();
        pool->procs[n].pid    = pid;
        pool->procs[n].status = udps_pool_proc_status_idle;
        udps_pool_update_stats(udps_pool_proc_status_ninit, udps_pool_proc_status_idle);
        udps_pool_lock_release();
        LOG_POOL(UDPS_LOG_NOTICE, ("Process %u forked: pid=%d", n, pid));
    } else if(pid == 0) { /* Child. */
        udps_pool_pff();
    } else {
        LOG_POOL(UDPS_LOG_CRIT, ("Unable to fork process %u: pid=%d", n, pid));
        return UDPS_ERR_POOL_FORK_FAIL;
    }

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_pool_kill(void)
{
    uchar      n;
    udps_err_t rc;

    LOG_POOL(UDPS_LOG_DEBUG, ("Trying to kill a process..."));

    /* The current number of active processes in the pool must not be lower
     * than UDPS_POOL_CLIENTS_MIN. */
    udps_pool_lock_wait_read();
    assert((pool->anum >= UDPS_POOL_CLIENTS_MIN));

    /* If the pool is currently at minimum, skip. */
    if(pool->anum == UDPS_POOL_CLIENTS_MIN) {
        LOG_POOL(UDPS_LOG_WARNING, ("Kill is not allow. Pool is currently "
                                    "at minimum: %u", pool->anum));
        return UDPS_ERR_POOL_MIN;
    }
    udps_pool_lock_release();

    /* Get first idle process. */
    rc = udps_pool_get_pnum(udps_pool_proc_status_idle, &n);
    if(rc != UDPS_OK) {
        LOG_POOL(UDPS_LOG_WARNING, ("Could not get an idle process. "
                                    "All processes are working"));
        return UDPS_ERR_POOL_ALL_WORK;
    }

    /* Kill a process. */
    if(kill(pool->procs[n].pid, SIGUSR1) != 0) {
        LOG_POOL(UDPS_LOG_CRIT, ("Could not kill process %u: pid=%d ; %s (%d)",
                                 n, pool->procs[n].pid, strerror(errno),
                                 errno));
        return UDPS_ERR_POOL_KILL_FAIL;
    }
    LOG_POOL(UDPS_LOG_NOTICE, ("Process %u killed: pid=%d",
                               n, pool->procs[n].pid));
    udps_pool_set_process_status(pool->procs[n].pid,
                                 udps_pool_proc_status_ninit);

    return UDPS_OK;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static udps_err_t udps_pool_get_pnum(udps_pool_proc_status_t pstatus,
                                     uchar* pnum)
{
    uint i;

    /* Check received parameters. */
    if(pnum == NULL) {
        LOG_POOL(UDPS_LOG_EMERG, ("Invalid received parameters"));
        return UDPS_ERR_RECV_PARAMS;
    }

    /* Get process. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Getting first process with status: %u...",
                              pstatus));
    udps_pool_lock_wait_read();
    for(i=0 ; i<UDPS_POOL_CLIENTS_MAX ; ++i) {
        if(pool->procs[i].status == pstatus) {
            LOG_POOL(UDPS_LOG_DEBUG, ("First process with status %u found: %u",
                                      pstatus, i));
            *pnum = i;
            udps_pool_lock_release();
            return UDPS_OK;
        }
    }
    udps_pool_lock_release();

    return UDPS_ERR_POOL_NINIT_NOT_FOUND;
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
void udps_pool_set_process_status(pid_t pid, udps_pool_proc_status_t pstatus)
{
    uint i;

    /* Check received parameters. */
    if(pid < 0) {
        LOG_POOL(UDPS_LOG_EMERG, ("Invalid received parameters"));
        return;
    }

    /* Change process status. */
    LOG_POOL(UDPS_LOG_DEBUG, ("Changing process (pid=%d) status to: %u...",
                              pid, pstatus));
    udps_pool_lock_wait_write();
    for(i=0 ; i<UDPS_POOL_CLIENTS_MAX ; ++i) {
        if(pool->procs[i].pid == pid) {
            udps_pool_update_stats(pool->procs[i].status, pstatus);
            if(pstatus == udps_pool_proc_status_ninit) {
                pool->procs[i].pid = 0;
            }
            pool->procs[i].status = pstatus;
            LOG_POOL(UDPS_LOG_DEBUG, ("New process %u (pid=%d) status: %u...",
                                      i, pool->procs[i].pid,
                                      pool->procs[i].status));
            udps_pool_lock_release();
            return;
        }
    }
    udps_pool_lock_release();
    LOG_POOL(UDPS_LOG_ERR, ("Process (pid=%d) not found in the pool", pid));
}
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static void udps_pool_update_stats(udps_pool_proc_status_t prev_status,
                                   udps_pool_proc_status_t new_status)
{
    /* Update poll statistics. */
    if(prev_status == udps_pool_proc_status_ninit) {
        ++pool->anum;
    } else if(prev_status == udps_pool_proc_status_idle) {
        --pool->inum;
    } else if(prev_status == udps_pool_proc_status_working) {
        --pool->wnum;
    }
    if(new_status == udps_pool_proc_status_ninit) {
        --pool->anum;
    } else if(new_status == udps_pool_proc_status_idle) {
        ++pool->inum;
    } else if(new_status == udps_pool_proc_status_working) {
        ++pool->wnum;
    }
}
/*----------------------------------------------------------------------------*/
