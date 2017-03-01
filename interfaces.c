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

#include "interfaces.h"

#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>

static char *
sockaddr_to_string(const struct sockaddr *addr)
{
  char addr_as_string[INET6_ADDRSTRLEN+1];
  size_t addr_len;

  switch (addr->sa_family) {
    case AF_INET: addr_len = sizeof (struct sockaddr_in); break;
    case AF_INET6: addr_len = sizeof (struct sockaddr_in6); break;
    default: return NULL;
  }

  if (getnameinfo (addr, addr_len,
          addr_as_string, sizeof (addr_as_string), NULL, 0,
          NI_NUMERICHOST) != 0) {
    return NULL;
  }

  return strdup(addr_as_string);
}

static int
ice_interfaces_is_private_ip (const struct sockaddr *_sa)
{
  union {
    const struct sockaddr *addr;
    const struct sockaddr_in *in;
  } sa;

  sa.addr = _sa;

  if (sa.addr->sa_family == AF_INET) {
    /* 10.x.x.x/8 */
    if (sa.in->sin_addr.s_addr >> 24 == 0x0A)
      return 1;

    /* 172.16.0.0 - 172.31.255.255 = 172.16.0.0/10 */
    if (sa.in->sin_addr.s_addr >> 20 == 0xAC1)
      return 1;

    /* 192.168.x.x/16 */
    if (sa.in->sin_addr.s_addr >> 16 == 0xC0A8)
      return 1;

    /* 169.254.x.x/16  (for APIPA) */
    if (sa.in->sin_addr.s_addr >> 16 == 0xA9FE)
      return 1;
  }
  
  return 0;
}


struct list_head*
ice_interfaces_get_local_ips (struct list_head *head, int include_loopback)
{
  struct ifaddrs *ifa, *results;

  if ( head == NULL ) 
     return NULL;

  if (getifaddrs (&results) < 0)
      return NULL;

  /* Loop through the interface list and get the IP address of each IF */
  for (ifa = results; ifa; ifa = ifa->ifa_next) {
    char *addr_string = NULL;

    if ( ifa->ifa_addr->sa_family==AF_INET6 )
      continue;

    /* no ip address from interface that is down */
    if ((ifa->ifa_flags & IFF_UP) == 0)
      continue;

    if (ifa->ifa_addr == NULL)
      continue;

    /* Convert to a string. */
    addr_string = sockaddr_to_string (ifa->ifa_addr);
    if (addr_string == NULL) {
      ICE_ERROR("Failed to convert address to string for interface, ifa_name:%s",
          ifa->ifa_name);
      continue;
    }

    ICE_DEBUG("Interface:  %s", ifa->ifa_name);
    ICE_DEBUG("IP Address: %s", addr_string);

    if ((ifa->ifa_flags & IFF_LOOPBACK) == IFF_LOOPBACK) {
      if (include_loopback) {
        //loopbacks = add_ip_to_list (loopbacks, addr_string, TRUE);
        ICE_DEBUG("FIXME: loopback interface");
      } else {
        ICE_DEBUG("Ignoring loopback interface");
      }
    } else {
      ICE_DEBUG("FIXME: order of ip addresses is important?");
      ice_interfaces_is_private_ip(ifa->ifa_addr);
      /*if (ice_interfaces_is_private_ip (ifa->ifa_addr))
        ips = add_ip_to_list (ips, addr_string, TRUE);
      else
        ips = add_ip_to_list (ips, addr_string, FALSE);*/
      address_t *addr = address_new();
      if (address_set_from_string(addr, addr_string) == ICE_OK) {
         ICE_DEBUG("add local address, addr=%s",addr_string);
         list_add(&addr->list,head);
      } else {
         ICE_ERROR("failed to parse local address, addr=%s",addr_string);
         address_free(addr);
      }
    }

    if ( addr_string != NULL )
       free(addr_string);
  }

  freeifaddrs (results);

  //if (loopbacks)
  //  ips = g_list_concat (ips, loopbacks);
  //return ips;
 
  return NULL;
}


