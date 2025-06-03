/*

   honggfuzz - logging
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

#ifndef _LOG_H
#define _LOG_H

#include <stdbool.h>

#define LOG_RAW(...) dprintf(logGetFD(), __VA_ARGS__);

#define LOG_HELP(...) logLog(HELP, __FUNCTION__, __LINE__, false, __VA_ARGS__);
#define LOG_HELP_BOLD(...) logLog(HELP_BOLD, __FUNCTION__, __LINE__, false, __VA_ARGS__);

#define LOG_D(...) if (logGetLogLevel() >= DEBUG) { logLog(DEBUG, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_I(...) if (logGetLogLevel() >= INFO) { logLog(INFO, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_W(...) if (logGetLogLevel() >= WARNING) { logLog(WARNING, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_E(...) if (logGetLogLevel() >= ERROR) { logLog(ERROR, __FUNCTION__, __LINE__, false, __VA_ARGS__); }
#define LOG_F(...) if (logGetLogLevel() >= FATAL) { logLog(FATAL, __FUNCTION__, __LINE__, false, __VA_ARGS__); }

#define PLOG_D(...) if (logGetLogLevel() >= DEBUG) { logLog(DEBUG, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_I(...) if (logGetLogLevel() >= INFO) { logLog(INFO, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_W(...) if (logGetLogLevel() >= WARNING) { logLog(WARNING, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_E(...) if (logGetLogLevel() >= ERROR) { logLog(ERROR, __FUNCTION__, __LINE__, true, __VA_ARGS__); }
#define PLOG_F(...) if (logGetLogLevel() >= FATAL) { logLog(FATAL, __FUNCTION__, __LINE__, true, __VA_ARGS__); }

enum llevel_t {
    FATAL = 0,
    ERROR,
    WARNING,
    INFO,
    DEBUG,
    HELP,
    HELP_BOLD
};

#ifdef __cplusplus
extern "C" {
#endif
void logSetLogLevel(enum llevel_t);
enum llevel_t logGetLogLevel(void);
int logGetFD();
bool logInitLogFile(const char *logfile, enum llevel_t ll);
void logLog(enum llevel_t ll, const char *fn, int ln, bool perr, const char *fmt, ...)
    __attribute__ ((format(printf, 5, 6)));
void logStop(int sig);
#ifdef __cplusplus
}
#endif

// courtesy of @pwntester on github
#if defined(__APPLE__)
  #if !defined(__NR_gettid)
    #define __NR_gettid SYS_gettid
  #endif
#endif

#endif                          /* _LOG_H */
