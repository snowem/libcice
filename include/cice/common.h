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
 * @(#)common.h
 */

#ifndef _CICE_COMMON_H_
#define _CICE_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef USE_LIBEVENT2

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#endif

#ifdef USE_ESP32

//#include <arpa/inet.h>
//#include <netdb.h>
//#include <netinet/in.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <lwip/sockets.h>
#include <tcpip_adapter.h>

//flags borrowed from libevents
#define EV_TIMEOUT  0x01
#define EV_READ     0x02
#define EV_WRITE    0x04
#define EV_SIGNAL   0x08
#define EV_PERSIST  0x10
#define EV_ET       0x20

#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b) \
 ((((__const uint32_t *) (a))[0] == ((__const uint32_t *) (b))[0]) \
 && (((__const uint32_t *) (a))[1] == ((__const uint32_t *) (b))[1]) \
 && (((__const uint32_t *) (a))[2] == ((__const uint32_t *) (b))[2]) \
 && (((__const uint32_t *) (a))[3] == ((__const uint32_t *) (b))[3]))
#endif //IN6_ARE_ADDR_EQUAL

#endif

#ifdef __cplusplus
}
#endif

#endif //_CICE_COMMON_H_


