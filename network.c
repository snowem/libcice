/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2006-2009 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2006-2009 Nokia Corporation. All rights reserved.
 *  Contact: Kai Vehmanen
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Dafydd Harries, Collabora Ltd.
 *   Youness Alaoui, Collabora Ltd.
 *   Kai Vehmanen, Nokia
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

/*
 * Porting to C library using libevent.
 * Jackie Dinh - 2016
 */


#include <errno.h>
#include <unistd.h>

#include "cice/address.h"
#include "cice/agent.h"
#include "cice/network.h"
#include "cice/stun.h"

int
stun_recv_message(socket_t *sock, address_t* from, char *buf, int len) {
   agent_t *agent;
   stream_t *stream;
   component_t *component;
   //address_t *addr;
   int ret = ICE_ERR;

   if ( sock == NULL || from == NULL ) {
      ICE_ERROR("socket pointer is null");
      return ICE_ERR;
   }
   agent = (agent_t*)sock->agent;
   stream = (stream_t*)sock->stream;
   component = (component_t*)sock->component;

   if ( agent == NULL || stream == NULL || component == NULL ) {
      ICE_ERROR("agent pointer is null");
      return ICE_ERR;
   }

   //1. check turn server candidate
   
   //2. dispatch msg
   agent->media_after_tick = ICE_TRUE;
   if ( is_validated_stun_message((uint8_t*)buf,len,1) > 0 ) {
      //2.1 handle inbound stun message
      //ICE_DEBUG("Handle inbound stun message");
      ret = conn_check_handle_inbound_stun(agent, stream, component, sock, from, buf, len);

   } else {
      //2.2 handle other data
      //ICE_DEBUG("Handle non-stun message");
      //HEXDUMP(buf,len,"msg");
      if ( component->io_callback ) {
         //ICE_DEBUG("call user-defined callback");
         //janus_ice_cb_nice_recv
         //typedef void (*agent_recv_func) (agent_t *agent, uint32_t stream_id, 
         //              uint32_t component_id, char *buf, uint32_t len, void  *user_data);
         component->io_callback(agent,stream->id,component->id, buf, len, component->io_data);
      }
      ret = ICE_OK;
   }

   //3. unhandled stun message
   
   return ret;
}

static void 
socket_udp_read_cb(evutil_socket_t fd, short what, void *ctx)
{
   static char buf[MAX_BUF_SIZE] = {0};
   socket_t *sock = (socket_t*)ctx;;
   struct sockaddr_in remaddr;
   address_t fromaddr;
   socklen_t addrlen;
   size_t recvlen;
   int ret;

   memset(&remaddr, 0, sizeof(remaddr));
   addrlen = sizeof(remaddr);

   recvlen = recvfrom(fd, buf, MAX_BUF_SIZE, 0, (struct sockaddr*)&remaddr, &addrlen);

   ICE_DEBUG("Receive data, fd=%u, ip=%u, port=%u, recvlen: %ld", 
        fd, remaddr.sin_addr.s_addr, ntohs(remaddr.sin_port), recvlen);
   if (recvlen <= 0) {
      ICE_ERROR("could not receive data, ret=%ld",recvlen);
      return;
   }   

   //ICE_HEXDUMP(buf,recvlen,"udp");
   ICE_DEBUG("get udp socket, agent=%p,stream=%p,component=%p",
         sock->agent,sock->stream,sock->component);
   memset(&fromaddr, 0, sizeof(fromaddr));
   address_set_from_sockaddr(&fromaddr,(const struct sockaddr*)&remaddr);
   address_set_port(&fromaddr,ntohs(remaddr.sin_port));
   print_address(&fromaddr);

   //FIXME: check order of udp packets or force no-udp-fragment?
   if (is_stun_message((uint8_t*)buf,recvlen,1) > 0) {
      ret = stun_recv_message(sock,&fromaddr,buf,recvlen);
      if ( ret < 0 ) {
         ICE_ERROR("failed to recv stun msg");
      }
   } else {

      agent_t *agent = (agent_t*)sock->agent;
      stream_t *s = (stream_t*)sock->stream;
      component_t *c = (component_t*)sock->component;
      if (c->io_callback) {
         //ice_data_recv_cb
         c->io_callback(agent,s->id,c->id,buf,recvlen,c->io_data);
      } else {
         ICE_ERROR("no io callback");
      }

   }

   return;
}


static void 
socket_tcp_read_cb(struct bufferevent *bev, void *ctx) {
   static char data[4*1024]={0};
   struct evbuffer *input_bev;
   agent_t *agent = (agent_t*)ctx;
   size_t recv_input_len;

   ICE_DEBUG("socket_udp_read_cb");

   if ( bev == 0) {
      return;
   }   
   
   input_bev = bufferevent_get_input(bev);
   recv_input_len = evbuffer_get_length(input_bev);
   evbuffer_remove(input_bev, data, recv_input_len);

   printf("buffer, agent=%p, len=%lu,data=%s\n",agent,recv_input_len,data);
   

}

static 
void socket_event_cb(struct bufferevent *bev, short events, void *ctx)
{
   if (events & BEV_EVENT_ERROR) {
      ICE_ERROR("buffer error, events=%u\n",events);
      return;
   }   

   if (events & ( BEV_EVENT_EOF |BEV_EVENT_ERROR) ) { 
      ICE_DEBUG("buffer end, events=%u\n",events);
   }   

   return;
}

socket_t*
udp_bsd_socket_new(agent_t *agent, stream_t *stream, component_t *component,  address_t *addr) {
   socket_t *sock = NULL;
   socklen_t addrlen = 0;
   struct event *ev=0;
   int fd = 0;

   sock = create_socket(agent->base,ICE_SOCKET_TYPE_UDP_BSD, addr, socket_udp_read_cb);
   //sock = socket_new(ICE_SOCKET_TYPE_UDP_BSD);
   if (sock == NULL)
      return NULL;
   sock->agent = agent;
   sock->stream = stream;
   sock->component = component;
   sock->addr = *addr;    
 
   if (addr->s.addr.sa_family == AF_INET) {
      fd = socket(AF_INET,SOCK_DGRAM,0);
      if (fd < 0) {
         ICE_ERROR("cannot create udp socket");
         return NULL;
      }
      if (bind(fd,&addr->s.addr,sizeof(addr->s.ip4)) < 0) {
         ICE_ERROR("failed to binding ip4");
         goto errors;
      }
      addrlen = sizeof(addr->s.ip4); 
      if (getsockname(fd, &addr->s.addr, &addrlen) < 0) {
         ICE_ERROR("getsockname failed");
         goto errors;
      }
      ICE_DEBUG("binding ip4, addrlen=%u,port=%u", addrlen,addr->s.ip4.sin_port);
   } else if (addr->s.addr.sa_family == AF_INET6) {
      fd = socket(AF_INET6,SOCK_DGRAM,0);
      if (fd < 0) {
         ICE_ERROR("cannot create udp socket");
         return NULL;
      }
      if (bind(fd,&addr->s.addr,sizeof(addr->s.ip6)) < 0) {
         ICE_ERROR("failed to binding ip6, errno=%d",errno);
         goto errors;
      }
      addrlen = sizeof(addr->s.ip6); 
      if (getsockname(fd, &addr->s.addr, &addrlen) < 0) {
         ICE_ERROR("getsockname failed");
         goto errors;
      }
      ICE_DEBUG("binding ip6, addrlen=%u,port=%u", addrlen,addr->s.ip4.sin_port);
   }


   //bev = bufferevent_socket_new(agent->base, 0, BEV_OPT_CLOSE_ON_FREE);
   ////bufferevent_setcb(bev, socket_udp_read_cb, NULL, socket_event_cb, agent);
   //bufferevent_enable(bev, EV_READ|EV_WRITE);
   
   //create_socket(base, socket, socket_udp_read_cb);
   ev = event_new(agent->base, fd, EV_READ|EV_PERSIST, socket_udp_read_cb, sock);
   event_add(ev, NULL);

   sock->ev = ev;

   sock->fd = fd;

   ICE_DEBUG("create udp socket, fd=%u, agent=%p,stream=%p,component=%p",
         fd, agent,stream,component);

   return sock;

errors:
   if (sock != NULL) 
      socket_free(sock);
   if ( fd > 0 ) 
      close(fd);
   return NULL;
}

socket_t*
tcp_active_socket_new(agent_t *agent, stream_t *stream, 
               component_t *component, address_t *addr) {
   socket_t *sock = socket_new(ICE_SOCKET_TYPE_TCP_ACTIVE);
   struct bufferevent *bev;
   int fd = 0;

   if ( sock == NULL || agent == NULL )
      return NULL;


   sock->addr = *addr;    

   //agent->base->create_event(base,sock, socket_udp_read_cb, write_cb, event_cb);
   fd = socket(AF_INET,SOCK_STREAM,0);
   evutil_make_socket_nonblocking(fd);
   bev = bufferevent_socket_new(agent->base, fd, BEV_OPT_CLOSE_ON_FREE);
   bufferevent_setcb(bev, socket_tcp_read_cb, NULL, socket_event_cb, agent);

   /* FIXME: can use only sock->ev for libevent */
   sock->bev = bev;

   return sock;
}

socket_t*
tcp_passive_socket_new(agent_t *agent, stream_t *stream, 
               component_t *component, address_t *addr) {
   socket_t *sock = socket_new(ICE_SOCKET_TYPE_TCP_PASSIVE);

   if ( sock == NULL )
      return NULL;

   sock->addr = *addr;    

   /* FIXME: setup io callbacks */

   return sock;
}

socket_t*
socket_new(IceSocketType type) {
   socket_t *sock;

   sock = ICE_MALLOC(socket_t);
   if (sock == NULL) 
      return NULL;

   ICE_MEMZERO(sock,socket_t);
   sock->type = type;
   
   return sock;
}


void
socket_free(socket_t *sock)
{
  if (!sock) return;

  if (sock->type == ICE_SOCKET_TYPE_UDP_BSD) {
    event_del(sock->ev);
  }
  close(sock->fd);
  ICE_FREE(sock);

  return;
}

int
udp_socket_send(socket_t *sock, const address_t *to, 
          const char *buf, size_t len)
{
   int n;
   //struct sockaddr_in serveraddr;

   if ( sock == NULL || to == NULL ) {
      ICE_ERROR("null pointer");
      return ICE_ERR;
   }

   //socket_send_messages
   //ICE_DEBUG("udp_socket_send, fd=%d",sock->fd);
   //print_address(to); 
   //HEXDUMP(buf,len,"udp_send");

   n = sendto(sock->fd, buf, len, 0, &to->s.addr, get_address_length(to));
   if ( n < 0 ) {
      ICE_ERROR("sendto error, ret=%d, fd=%d, len=%lu,",n,sock->fd,len);
      return ICE_ERR;
   }

   return n;
}

size_t
tcp_passive_socket_send(socket_t *sock, const address_t *to, 
           size_t len, const char *buf)
{
   //socket_send_messages
   ICE_DEBUG("FIXME: tcp_pass_socket_send");
   return 0;
}

size_t
tcp_active_socket_send(socket_t *sock, const address_t *to, 
          size_t len, const char *buf)
{
   //socket_send_messages
   ICE_DEBUG("FIXME: tcp_active_socket_send");
   return 0;
}


int
socket_is_reliable(socket_t *sock)
{
   //FIXME: have different types of socket_t 
   return 0;
}




