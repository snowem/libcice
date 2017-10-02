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


#ifndef _CANDIDATE_H_
#define _CANDIDATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "address.h"

typedef enum
{
  ICE_CANDIDATE_TYPE_HOST,
  ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
  ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
  ICE_CANDIDATE_TYPE_RELAYED,
  ICE_CANDIDATE_TYPE_LAST,
} IceCandidateType;

typedef enum
{
  ICE_CANDIDATE_TRANSPORT_UDP,
  ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE,
  ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE,
  ICE_CANDIDATE_TRANSPORT_TCP_SO,
} IceCandidateTransport;

typedef enum {
  ICE_RELAY_TYPE_TURN_UDP,
  ICE_RELAY_TYPE_TURN_TCP,
  ICE_RELAY_TYPE_TURN_TLS
} IceRelayType;

typedef enum {
  ADD_HOST_MIN = 0, 
  ADD_HOST_UDP = ADD_HOST_MIN,
  ADD_HOST_TCP_ACTIVE,
  ADD_HOST_TCP_PASSIVE,
  ADD_HOST_MAX = ADD_HOST_TCP_PASSIVE
} AddHostType;

struct _turnserver
{
  int32_t ref_count;
  address_t server;
  char *username;
  char *password;
  IceRelayType type;
};


struct _candidate
{
  struct list_head list;
  IceCandidateType type;
  IceCandidateTransport transport;
  address_t addr;
  address_t base_addr;
  uint32_t priority;
  uint32_t stream_id;
  uint32_t component_id;
  char foundation[ICE_CANDIDATE_MAX_FOUNDATION];
  char *username;        /* pointer to a nul-terminated username string */
  char *password;        /* pointer to a nul-terminated password string */
  void *sockptr;

  turnserver_t *turn;
};


candidate_t *
candidate_new(IceCandidateType type);

void
candidate_free(candidate_t *candidate);

candidate_t*
candidate_copy (const candidate_t *candidate);

uint32_t
candidate_jingle_priority (candidate_t *candidate);

uint32_t
candidate_msn_priority (candidate_t *candidate);

uint32_t
candidate_ms_ice_priority (const candidate_t *candidate,
    int reliable, int nat_assisted);

uint32_t
candidate_ice_priority (const candidate_t *candidate,
    int reliable, int nat_assisted);

uint64_t
candidate_pair_priority(uint32_t o_prio, uint32_t a_prio);


void
print_candidate(candidate_t *c, char *msg);

#ifdef __cplusplus
}
#endif

#endif //_CANDIDATE_H_


