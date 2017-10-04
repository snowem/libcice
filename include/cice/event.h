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
 * @(#)event.h
 */

#ifndef _CICE_EVENT_H_
#define _CICE_EVENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cice/types.h"

typedef enum {
  ICE_SOCKET_TYPE_UDP_BSD,
  ICE_SOCKET_TYPE_TCP_BSD,
  ICE_SOCKET_TYPE_PSEUDOSSL,
  ICE_SOCKET_TYPE_HTTP,
  ICE_SOCKET_TYPE_SOCKS5,
  ICE_SOCKET_TYPE_UDP_TURN,
  ICE_SOCKET_TYPE_UDP_TURN_OVER_TCP,
  ICE_SOCKET_TYPE_TCP_ACTIVE,
  ICE_SOCKET_TYPE_TCP_PASSIVE,
  ICE_SOCKET_TYPE_TCP_SO
} IceSocketType;



struct _socket {
   int   fd;
   IceSocketType type;
   /* TODO: abstract network layer 
    * to support epoll, select, kqueue etc */
   struct event *ev;
   struct bufferevent *bev;
   address_t addr;
   void     *agent;
   void     *stream;
   void     *component;
};


typedef void (*event_callback_func)(int fd, short event, void *arg);

typedef socket_t* (*create_socket_func)(event_ctx_t *ctx, socket_t* sock, event_callback_func cb);
typedef void  (*destroy_socket_func)(int fd, short port, int family);
typedef event_info_t* (*create_event_func)(event_ctx_t *ctx, int type, event_callback_func cb, int timeout);
typedef void  (*destroy_event_func)(event_ctx_t *ctx, event_info_t *ev);

struct _event_ctx {
  agent_t             *agent;

#ifdef USE_LIBEVENT2
  struct event_base   *base;
#endif

#ifdef USE_ESP32
#endif

  create_socket_func   create_socket;
  destroy_socket_func  destroy_socket;
  create_event_func   create_event;
  destroy_event_func  destroy_event;
};

struct _event_info {
  event_ctx_t         *ctx;
#ifdef USE_LIBEVENT2
  struct event        *ev;
  event_callback_func  cb;
#endif

#ifdef USE_ESP32
#endif
};

event_ctx_t*
create_event_ctx();

socket_t*
create_socket(event_ctx_t *ctx, IceSocketType type, address_t *addr, event_callback_func cb);

void
destroy_socket(event_ctx_t *ctx, socket_t *sock);

event_info_t*
create_event_info(event_ctx_t *ctx, int type, event_callback_func cb, int timeout);

void
destroy_event_info(event_ctx_t *ctx, event_info_t *ev);

#ifdef __cplusplus
}
#endif

#endif //_CICE_EVENT_H_


