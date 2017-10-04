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

#ifndef _ICE_NETWORK_H_
#define _ICE_NETWORK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>

#include "cice/address.h"
#include "cice/common.h"
#include "cice/event.h"
#include "cice/log.h"
#include "cice/types.h"

socket_t*
udp_bsd_socket_new(agent_t *agent, stream_t *stream, component_t *c,  address_t *addr);

socket_t*
tcp_active_socket_new(agent_t *agent, stream_t *stream, component_t *c, address_t *addr);

socket_t*
tcp_passive_socket_new(agent_t *agent, stream_t *stream, component_t *c, address_t *addr);

socket_t*
socket_new(IceSocketType type);

void
socket_free(socket_t *sock);

int
udp_socket_send(socket_t *sock, const address_t *to, 
          const char *buf, size_t len);
size_t
tcp_passive_socket_send(socket_t *sock, const address_t *to, 
       size_t len, const char *buf);

size_t
tcp_active_socket_send(socket_t *sock, const address_t *to, 
       size_t len, const char *buf);

int
socket_is_reliable(socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif //_NETWORK_H_





