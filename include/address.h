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

#ifndef _ICE_ADDRESS_H_
#define _ICE_ADDRESS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "list.h"

struct _address
{
   struct list_head list;
   union
   {
     struct sockaddr     addr;
     struct sockaddr_in  ip4;
     struct sockaddr_in6 ip6;
   } s;
};

#define ICE_ADDRESS_STRING_LEN INET6_ADDRSTRLEN

address_t*
address_new(void);

void
address_free(address_t *addr);

void
address_to_string(const address_t *addr, char *dst);

void
address_set_port(address_t *addr, uint16_t port);

int
address_equal_no_port(const address_t *a, const address_t *b);

int
address_equal(const address_t *a, const address_t *b);

void
print_address(const address_t *addr);

uint32_t
address_get_port(const address_t *addr);

int
address_set_from_string(address_t *addr, const char *str);

int
address_is_valid(const address_t *a);

void
address_set_from_sockaddr (address_t *addr,
         const struct sockaddr *sa);

void
address_copy_to_sockaddr(const address_t *addr, struct sockaddr *_sa);

int
get_address_length(const address_t *addr);

address_t *
address_dup(const address_t *a);

void
address_init(address_t *addr);

int
address_is_private(const address_t *a);

#ifdef __cplusplus
}
#endif

#endif //_ADDRESS_H_







