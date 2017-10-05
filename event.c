/*
 * Copyright (c) 2017 Jackie Dinh <jackiedinh8@gmail.com>
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
 * @(#)event.c
 */

#include "cice/address.h"
#include "cice/common.h"
#include "cice/event.h"
#include "cice/log.h"
#include "cice/socket.h"

#ifdef USE_LIBEVENT2

void
libevent2_init_udp_socket(socket_t *sock) {
  address_t *addr = &sock->addr;
  socklen_t addrlen = 0;
  int fd;

  if (addr->s.addr.sa_family == AF_INET) {
    fd = socket(AF_INET,SOCK_DGRAM,0);
    if (fd < 0) {
      ICE_ERROR("cannot create udp socket");
       return;
    }
    if (bind(fd,&addr->s.addr,sizeof(addr->s.ip4)) < 0) {
       ICE_ERROR("failed to binding ip4");
       return;
    }
    addrlen = sizeof(addr->s.ip4); 
    if (getsockname(fd, &addr->s.addr, &addrlen) < 0) {
       ICE_ERROR("getsockname failed");
       return;
    }
    ICE_DEBUG("binding ip4, addrlen=%u,port=%u", addrlen,addr->s.ip4.sin_port);
  } else if (addr->s.addr.sa_family == AF_INET6) {
    fd = socket(AF_INET6,SOCK_DGRAM,0);
    if (fd < 0) {
       ICE_ERROR("cannot create udp socket");
       return;
    }
    if (bind(fd,&addr->s.addr,sizeof(addr->s.ip6)) < 0) {
       ICE_ERROR("failed to binding ip6, errno=%d",errno);
       return;
    }
    addrlen = sizeof(addr->s.ip6); 
    if (getsockname(fd, &addr->s.addr, &addrlen) < 0) {
       ICE_ERROR("getsockname failed");
       return;
    }
    ICE_DEBUG("binding ip6, addrlen=%u,port=%u", addrlen,addr->s.ip4.sin_port);
  }
  sock->fd = fd;
  return;
}

void
libevent2_init_tcp_socket(socket_t *sock) {
  return;
}

socket_t*
libevent2_create_socket(event_ctx_t *ctx, socket_t* sock, event_callback_func cb) {
  struct event *ev = 0;

  if (!sock) return NULL;

  switch(sock->type) {
    case ICE_SOCKET_TYPE_UDP_BSD:
      libevent2_init_udp_socket(sock);
      break;
    case ICE_SOCKET_TYPE_TCP_BSD:
      libevent2_init_tcp_socket(sock);
      break;
    default:
      return NULL;
  }

   ev = event_new(ctx->base, sock->fd, EV_READ|EV_PERSIST, cb, sock); //socket_udp_read_cb
   event_add(ev, NULL);
   sock->ev = ev;

  return sock;
}

void
libevent2_destroy_socket(int fd, short port, int family) {

  return;
}

event_info_t*
libevent2_create_event(event_ctx_t *ctx, int type, event_callback_func cb, int timeout) {
  event_info_t *ev = 0;
  struct timeval time_interval;
  struct event *time_ev;

  if (!ctx) return 0;

  ev = (event_info_t*)malloc(sizeof(event_info_t));
  if (ev == NULL) {
    return 0;
  }
  memset(ev,0,sizeof(event_info_t));
  
  ev->ctx = ctx;
  time_interval.tv_sec = 0;
  time_interval.tv_usec = timeout;
  time_ev = event_new(ctx->agent->base->base,-1,type,cb,ctx->agent);
  event_add(time_ev, &time_interval);
  ev->ev = time_ev;

  return ev;
}

void
libevent2_destroy_event(event_ctx_t *ctx, event_info_t *ev) {

  event_del(ev->ev);
  return;
}
#endif

#ifdef USE_ESP32
socket_t*
esp32_create_socket(event_ctx_t *ctx, socket_t* sock, event_callback_func cb) {

  return NULL;
}

void
esp32_destroy_socket(int fd, short port, int family) {

  return;
}

event_info_t*
esp32_create_event(event_ctx_t *ctx, int type, event_callback_func cb, int timeout) {

  return NULL;
}

void
esp32_destroy_event(event_ctx_t *ctx, event_info_t *ev) {

  return;
}

#endif //USE_ESP32

event_ctx_t*
create_event_ctx() {
  event_ctx_t *ctx = 0;

  ctx = (event_ctx_t*)malloc(sizeof(event_ctx_t));
  if (ctx == NULL) {
    return NULL;
  }
  memset(ctx,0,sizeof(event_ctx_t));

#ifdef USE_LIBEVENT2
  ctx->base = event_base_new();
  if (ctx->base == NULL ) {
    ICE_ERROR("failed to create event_base");
    return NULL;
  }
  ctx->dns_base = evdns_base_new(ctx->base, 1);
  ICE_ERROR("dns_base=%p", ctx->dns_base);

  ctx->create_socket = libevent2_create_socket;
  ctx->destroy_socket = libevent2_destroy_socket;
  ctx->create_event = libevent2_create_event;
  ctx->destroy_event = libevent2_destroy_event;
#endif

#ifdef USE_ESP32
  ctx->create_socket = esp32_create_socket;
  ctx->destroy_socket = esp32_destroy_socket;
  ctx->create_event = esp32_create_event;
  ctx->destroy_event = esp32_destroy_event;
#endif

  return ctx;
}

socket_t*
create_socket(event_ctx_t *ctx, IceSocketType type, address_t *addr, event_callback_func cb) {
  socket_t *sock;

  sock = socket_new(ICE_SOCKET_TYPE_UDP_BSD);
  if (sock == NULL)
    return NULL;
  sock->addr = *addr;

  //setup socket specifics
  return ctx->create_socket(ctx,sock,cb);
}

void
destroy_socket(event_ctx_t *ctx, socket_t *sock) {
  //FIXME
  return;
}

event_info_t*
create_event_info(event_ctx_t *ctx, int type, event_callback_func cb, int timeout) {
  return ctx->create_event(ctx,type,cb,timeout);
}

void
destroy_event_info(event_ctx_t *ctx, event_info_t *ev) {

  if (!ev) return;

  ctx->destroy_event(ctx, ev);
  return;
}

//create_timer(agent->base,priv_conn_keepalive_tick);






