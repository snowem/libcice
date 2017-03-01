/*
 * Copyright (c) 2016 Jackie Dinh <jackiedinh8@gmail.com>
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
 * @(#)utils.h
 */

#include "utils.h"

/* resolve seconds carry */
static inline void update_tv(struct timeval *t1)
{
  while (t1->tv_usec >= MILLION_I) {
    t1->tv_sec++;
    t1->tv_usec -= MILLION_I;
  }
  while (t1->tv_usec < 0) {
    t1->tv_sec--;
    t1->tv_usec += MILLION_I;
  }
}

void
add_microseconds_to_timeval(struct timeval *t, uint32_t microseconds) {
   if (t == NULL )
      return;
   t->tv_usec += microseconds;
   update_tv(t);
}

/*void timeval_add(struct timeval *t1, struct timeval *t2)
{
  t1->tv_sec += t2->tv_sec;
  t1->tv_usec += t2->tv_usec;
  update_tv(t1);
}*/

void
print_timeval(struct timeval *t) {
   if ( t != NULL )
      ICE_DEBUG("timevale info, tv_sec=%lu, tv_usec=%lu",t->tv_sec,t->tv_usec);
   return;
}


