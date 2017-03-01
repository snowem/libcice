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

#include "address.h"

#include <arpa/inet.h>

address_t*
address_new(void) {
   address_t *addr;
   addr = ICE_MALLOC(address_t);
   if (addr == NULL)
     return NULL;

   addr->s.addr.sa_family = AF_UNSPEC;
   memset (&addr->s, 0, sizeof(addr->s));

   return addr;
}

void
address_free(address_t *addr) {
   if ( addr == NULL )
      return;
   free(addr);
   return;
}

void
address_to_string(const address_t *addr, char *dst) {
   switch (addr->s.addr.sa_family) {
      case AF_INET:
         inet_ntop(AF_INET, &addr->s.ip4.sin_addr, dst, INET_ADDRSTRLEN);
         break;
      case AF_INET6:
         inet_ntop(AF_INET6, &addr->s.ip6.sin6_addr, dst, INET6_ADDRSTRLEN);
         break;
      default:
         break;
   }
   return;
}

void
address_set_port(address_t *addr, uint16_t port) {
   if (addr == NULL)
      return;

   switch (addr->s.addr.sa_family) {
      case AF_INET:
         addr->s.ip4.sin_port = htons (port);
         break;
      case AF_INET6:
         addr->s.ip6.sin6_port = htons (port);
         break;
      default:
         break;
   }
   return;
}

int
address_equal_no_port(const address_t *a, const address_t *b) {
   if (a == NULL || b == NULL)
      return 0;

   if (a->s.addr.sa_family != b->s.addr.sa_family)
      return 0;

   switch (a->s.addr.sa_family) {
      case AF_INET:
         return (a->s.ip4.sin_addr.s_addr == b->s.ip4.sin_addr.s_addr);

      case AF_INET6:
         return IN6_ARE_ADDR_EQUAL(&a->s.ip6.sin6_addr, &b->s.ip6.sin6_addr)
                && (a->s.ip6.sin6_scope_id == b->s.ip6.sin6_scope_id);

      default:
         break;
   }
   return 0;
}

int
address_equal(const address_t *a, const address_t *b) {
   if (a == NULL || b == NULL)
      return 0;

   if (a->s.addr.sa_family != b->s.addr.sa_family)
      return 0;

   switch (a->s.addr.sa_family) {
      case AF_INET:
         return (a->s.ip4.sin_addr.s_addr == b->s.ip4.sin_addr.s_addr)
                && (a->s.ip4.sin_port == b->s.ip4.sin_port);

      case AF_INET6:
         return IN6_ARE_ADDR_EQUAL(&a->s.ip6.sin6_addr, &b->s.ip6.sin6_addr)
                && (a->s.ip6.sin6_port == b->s.ip6.sin6_port)
                && (a->s.ip6.sin6_scope_id == b->s.ip6.sin6_scope_id);

      default:
         return 0;
   }
   return 0;
}

void
print_address(const address_t *addr) { 
   char local_ip[ICE_ADDRESS_STRING_LEN] = {0};
   address_to_string(addr, local_ip);
   ICE_DEBUG("address info, addr=%s,port=%u",
             local_ip,address_get_port(addr));
   return;
}

uint32_t
address_get_port(const address_t *addr) {
   if (!addr)
      return 0;

   switch (addr->s.addr.sa_family) {
      case AF_INET:
         return ntohs (addr->s.ip4.sin_port);
      case AF_INET6:
         return ntohs (addr->s.ip6.sin6_port);
      default:
         return 0;
   }

   return 0;
}

void
address_set_from_sockaddr (address_t *addr, const struct sockaddr *sa) {
  switch (sa->sa_family) {
      case AF_INET:
         memcpy(&addr->s.ip4, sa, sizeof (addr->s.ip4));
         break;
      case AF_INET6:
         memcpy(&addr->s.ip6, sa, sizeof (addr->s.ip6));
         break;
      default:
         break;
   }

   return;
}

int
address_set_from_string(address_t *addr, const char *str) {
  struct addrinfo hints;
  struct addrinfo *res;

  memset(&hints, 0, sizeof (hints));

  /* AI_NUMERICHOST prevents getaddrinfo() from doing DNS resolution. */
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;

  if (getaddrinfo (str, NULL, &hints, &res) != 0) {
     ICE_ERROR("failed to get addrinfo, str=%s",str);
     return ICE_ERR;  /* invalid address */
  }

  address_set_from_sockaddr(addr, res->ai_addr);
  freeaddrinfo(res);
  return ICE_OK;
}

int
address_is_valid(const address_t *a) {
   switch (a->s.addr.sa_family) {
      case AF_INET:
      case AF_INET6:
         return ICE_TRUE;
      default:
         return ICE_FALSE;
   }
   return ICE_FALSE;
}

void
address_copy_to_sockaddr(const address_t *addr, struct sockaddr *_sa) {
   union {
      struct sockaddr *addr;
      struct sockaddr_in *in;
      struct sockaddr_in6 *in6;
   } sa; 

   sa.addr = _sa;
   if (_sa == NULL )
      return;

   switch (addr->s.addr.sa_family) {   
      case AF_INET:
         memcpy (sa.in, &addr->s.ip4, sizeof (*sa.in));
         break;
      case AF_INET6:
         memcpy (sa.in6, &addr->s.ip6, sizeof (*sa.in6));
         break;
      default:
         return;
   }   
   return;
}

int
get_address_length (const address_t *addr) {
   int len = 0;
   switch (addr->s.addr.sa_family) {
      case AF_INET:
         //inet_ntop (AF_INET, &addr->s.ip4.sin_addr, dst, INET_ADDRSTRLEN);
         len = sizeof(addr->s.ip4);
         break;
      case AF_INET6:
         //inet_ntop (AF_INET6, &addr->s.ip6.sin6_addr, dst, INET6_ADDRSTRLEN);
         len = sizeof(addr->s.ip6);
         break;
      default:
         break;
   }
   return len;
}

address_t *
address_dup(const address_t *a) {
   address_t *dup = ICE_MALLOC(address_t);
   *dup = *a;
   INIT_LIST_HEAD(&dup->list);
   return dup;
}

void
address_init(address_t *addr) {
   if (addr == NULL)
      return;
   addr->s.addr.sa_family = AF_UNSPEC;
   memset(&addr->s, 0, sizeof(addr->s));
   INIT_LIST_HEAD(&addr->list);
   return;
}

static int
ipv4_address_is_private(uint32_t addr) { 
   addr = ntohl (addr);
  
   /* http://tools.ietf.org/html/rfc3330 */
   return (
      /* 10.0.0.0/8 */
      ((addr & 0xff000000) == 0x0a000000) ||
      /* 172.16.0.0/12 */
      ((addr & 0xfff00000) == 0xac100000) ||
      /* 192.168.0.0/16 */ 
      ((addr & 0xffff0000) == 0xc0a80000) ||
      /* 127.0.0.0/8 */
      ((addr & 0xff000000) == 0x7f000000));
}


static int
ipv6_address_is_private(const unsigned char *addr) {
   return (
      /* fe80::/10 */
      ((addr[0] == 0xfe) && ((addr[1] & 0xc0) == 0x80)) ||
      /* fc00::/7 */
      ((addr[0] & 0xfe) == 0xfc) ||
      /* ::1 loopback */
      ((memcmp (addr, "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x01", 16) == 0))); 
}

int
address_is_private(const address_t *a) 
{
   switch (a->s.addr.sa_family) {   
      case AF_INET:
         return ipv4_address_is_private (a->s.ip4.sin_addr.s_addr);
      case AF_INET6:
         return ipv6_address_is_private (a->s.ip6.sin6_addr.s6_addr);
      default:
         return 0;
   }   
   return 0;
}

