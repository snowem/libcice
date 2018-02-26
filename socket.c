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
 * @(#)socket.c
 */


#include <errno.h>
#include <unistd.h>

#include "cice/socket.h"

typedef int (*recvfrom_func)(int sockfd, void *buf, size_t len, int flags, 
                struct sockaddr *src_addr, socklen_t *addrlen);
typedef int (*sendto_func)( int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen);   
typedef int (*read_func)(int fd, void *buf, size_t count);   
typedef int (*write_func)(int fd, const void *buf, size_t count);   

#ifdef USE_LIBEVENT2
int libevent2_recvfrom(int fd, void *buf, size_t len, int flags, 
                struct sockaddr *src_addr, socklen_t *addrlen) {
  return recvfrom(fd, buf, len, 0, src_addr, addrlen);
}

int libevent2_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
  return sendto(fd, buf, len, 0, dest_addr, addrlen);
}

int libevent2_read(int fd, void *buf, size_t count) {

  return 0;
}

int libevent2_write(int fd, const void *buf, size_t count) {

  return 0;
}

#endif //USE_LIBEVENT2

#ifdef USE_ESP32
int esp32_recvfrom(int fd, void *buf, size_t len, int flags, 
                struct sockaddr *src_addr, socklen_t *addrlen) {
  //FIXME: change it to FreeRTOS api
  return recvfrom(fd, buf, len, 0, src_addr, addrlen);
}

int esp32_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
  return sendto(fd, buf, len, 0, dest_addr, addrlen);
}

int esp32_read(int fd, void *buf, size_t count) {

  return 0;
}

int esp32_write(int fd, const void *buf, size_t count) {

  return 0;
}

#endif //USE_ESP32

socket_t*
socket_new(IceSocketType type) {
   socket_t *sock;

   sock = ICE_MALLOC(socket_t);
   if (sock == NULL) 
      return NULL;

   ICE_MEMZERO(sock,socket_t);
   sock->type = type;
   
#ifdef USE_LIBEVENT2
   sock->_recvfrom = libevent2_recvfrom;
   sock->_sendto = libevent2_sendto;
   sock->_read = libevent2_read;
   sock->_write = libevent2_write;
#endif //USE_LIBEVENT2

#ifdef USE_ESP32
   sock->_recvfrom = esp32_recvfrom;
   sock->_sendto = esp32_sendto;
   sock->_read = esp32_read;
   sock->_write = esp32_write;
#endif //USE_ESP32

   return sock;
}


void
socket_free(socket_t *sock)
{
  if (!sock) return;

  //FIXME: socket_free should be replaced by destroy_socket.
  /*if (sock->type == ICE_SOCKET_TYPE_UDP_BSD) {
    event_del(sock->ev);
  }*/

  close(sock->fd);
  ICE_FREE(sock);

  return;
}


int
socket_is_reliable(socket_t *sock)
{
   //FIXME: have different types of socket_t 
   return 0;
}




