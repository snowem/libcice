/*
 * Copyright (c) 2015 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1 Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  2 Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *  3 Neither the name of the <organization> nor the 
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @(#)log.c
 */

#include "log.h"

#define _WITH_DPRINTF
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdarg.h>

#include "types.h"

int g_verbose = 1;
int g_log_fd = -1;
int g_log_level = ICE_LOG_ERROR;
ice_log_cb g_ice_log_cb = NULL;

void
log_init(char* file, int level)
{
   g_ice_log_cb = NULL;
   if ( level >= ICE_LOG_INFO && level <= ICE_LOG_FATAL )
      g_log_level = level;
   else 
      g_log_level = ICE_LOG_ERROR;

   if (file) {
      g_log_fd = ICE_OPEN(file, O_WRONLY|O_CREAT);
      if (g_log_fd < 0) {
         fprintf(stderr,"can not open log file, ret=%u\n",g_log_fd);
      }
   }

   return;
}

void 
ice_set_log_callback(ice_log_cb cb) {
   g_ice_log_cb = cb;
   return;
}

void 
ice_log_internal(int severity, const char *msg) {
   if (g_ice_log_cb) {
      g_ice_log_cb(severity,msg);
      return;
   }

   //if defing log file, write msg to the file.

   return;
}

void 
ice_log(int severity, const char *fmt, ...) {
   char buffer[10*1024];
   va_list argptr;
   
   if (severity >= g_log_level || !g_ice_log_cb)
      return;

   va_start(argptr, fmt);
   vsnprintf(buffer, 10*1024, fmt, argptr);
   va_end(argptr);
   ice_log_internal(severity,buffer);
   return;
}

/*void log(int level, const char* sourcefilename, int line, const char* msg, ...) {
    static const char* level_str[] = 
            {"INFO", "DEBUG", "WARN", "ERROR", "FATAL"};

    if ( g_log_fd < 0 )
       return;

    if (level >= g_log_level) {
        char dest[5*1024] = {0};
        va_list argptr;
        va_start(argptr, msg);
        vsnprintf(dest, 5*1024, msg, argptr);
        va_end(argptr);
        dprintf(g_log_fd, "[%s|%s:%d]: %s\n", level_str[level], sourcefilename, line,  dest);
    }

    return;
}*/



