/*

   nsjail - logging
   -----------------------------------------

   Copyright 2014 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sys/syscall.h>
#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

static int log_fd = STDERR_FILENO;
static bool log_fd_isatty = true;
enum llevel_t log_level = DEBUG;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void logSetLogLevel(enum llevel_t level) {
	log_level = level;
}

enum llevel_t logGetLogLevel(void)
{
    return log_level;
}

/*
 * Log to stderr by default. Use a dup()d fd, because in the future we'll associate the
 * connection socket with fd (0, 1, 2).
 */
bool logInitLogFile(const char *logfile, enum llevel_t ll)
{
    log_fd_isatty = (isatty(log_fd) == 1 ? true : false);
    log_level = ll;

    if (logfile == NULL) {
        return true;
    }

    log_fd = open(logfile, O_CREAT | O_RDWR | O_APPEND, 0640);
    if (log_fd == -1) {
        log_fd = STDERR_FILENO;
        PLOG_E("Couldn't open logfile open('%s')", logfile);
        return false;
    }
    log_fd_isatty = (isatty(log_fd) == 1 ? true : false);
    return true;
}

void logLog(enum llevel_t ll, const char *fn, int ln, bool perr, const char *fmt, ...)
{
    char strerr[512];
    if (perr == true) {
        snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
    }
    struct ll_t {
        char *descr;
        char *prefix;
        bool print_funcline;
    };
    struct ll_t logLevels[] = {
        {"F", "\033[7;35m", true},
        {"E", "\033[1;31m", true},
        {"W", "\033[0;33m", true},
        {"I", "\033[1m", true},
        {"D", "\033[0;4m", true},
        {"HR", "\033[0m", false},
        {"HB", "\033[1m", false},
    };

    time_t ltstamp = time(NULL);
    struct tm utctime;
    localtime_r(&ltstamp, &utctime);
    char timestr[32];
    if (strftime(timestr, sizeof(timestr) - 1, "%FT%T%z", &utctime) == 0) {
        timestr[0] = '\0';
    }

    /* Start printing logs */
    pthread_mutex_lock(&log_mutex);
    if (log_fd_isatty) {
        dprintf(log_fd, "%s", logLevels[ll].prefix);
    }
    if (logLevels[ll].print_funcline) {
#ifdef __FreeBSD__
        dprintf(log_fd, "[%s][%s][%d] %s():%d ", timestr, logLevels[ll].descr, (pid_t)pthread_getthreadid_np, fn, ln);
#elif __OpenBSD__
        dprintf(log_fd, "[%s][%s][%d] %s():%d ", timestr, logLevels[ll].descr, getpid(), fn, ln);
#else
        dprintf(log_fd, "[%s][%s][%d] %s():%d ", timestr, logLevels[ll].descr, (pid_t)syscall(__NR_gettid), fn, ln);
#endif
    }

    va_list args;
    va_start(args, fmt);
    vdprintf(log_fd, fmt, args);
    va_end(args);

    if (perr == true) {
        dprintf(log_fd, ": %s", strerr);
    }
    if (log_fd_isatty) {
        dprintf(log_fd, "\033[0m");
    }
    dprintf(log_fd, "\n");
    pthread_mutex_unlock(&log_mutex);
    /* End printing logs */

    if (ll == FATAL) {
        exit(1);
    }
}

void logStop(int sig)
{
    LOG_I("Server stops due to fatal signal (%d) caught. Exiting", sig);
}

void logRedirectLogFD(int fd)
{
    log_fd = fd;
}

int logGetFD() {
	return log_fd;
}

void logDirectlyToFD(const char *msg)
{
    dprintf(log_fd, "%s", msg);
}
