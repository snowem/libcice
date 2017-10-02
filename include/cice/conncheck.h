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

#ifndef _ICE_CONNCHECK_H_
#define _ICE_CONNCHECK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "candidate.h"
#include "list.h"
#include "log.h"
#include "stun/constants.h"
#include "stun/usages/timer.h"
#include "stun/stunmessage.h"
#include "types.h"

typedef enum
{
  ICE_CHECK_WAITING = 1,
  ICE_CHECK_IN_PROGRESS,
  ICE_CHECK_SUCCEEDED,
  ICE_CHECK_FAILED,
  ICE_CHECK_FROZEN,
  ICE_CHECK_CANCELLED,
  ICE_CHECK_DISCOVERED,
} IceCheckState;


struct _candidate_check_pair
{
  struct list_head list;
  agent_t *agent;
  uint32_t stream_id;
  uint32_t component_id;
  candidate_t *local;
  candidate_t *remote;
  socket_t    *sockptr;
  char foundation[ICE_CANDIDATE_PAIR_MAX_FOUNDATION];
  IceCheckState state;
  int nominated;
  int controlling;
  int timer_restarted;
  uint64_t priority;
  struct timeval next_tick;
  uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE_IPV6];
  StunTimer timer;
  StunMessage stun_message;
};

typedef struct {
  agent_t *agent;
  stream_t *stream;
  component_t *component;
  uint8_t *password;
} conncheck_validater_data;

int 
conn_check_add_for_local_candidate (agent_t *agent, 
  uint32_t stream_id, component_t *component, candidate_t *local);

int
conn_check_add_for_candidate_pair(agent_t *agent,
    uint32_t stream_id, component_t *component, 
    candidate_t *local, candidate_t *remote);

int 
conn_check_add_for_candidate(agent_t *agent, uint32_t stream_id, 
   component_t *component, candidate_t *remote);

void 
conn_check_remote_candidates_set(agent_t *agent);

int 
conn_check_schedule_next(agent_t *agent);

int 
conn_check_handle_inbound_stun(agent_t *agent, stream_t *stream,
    component_t *component, socket_t *nicesock, const address_t *from,
    char *buf, int len);

int 
conncheck_stun_validater(StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
        uint8_t **password, size_t *password_len, void *user_data);

IceCandidateTransport
conn_check_match_transport(IceCandidateTransport transport);

size_t priv_create_username(agent_t *agent, stream_t *stream,
    uint32_t component_id, candidate_t *remote, candidate_t *local,
    uint8_t *dest, uint32_t dest_len, int inbound);

size_t priv_get_password(agent_t *agent, stream_t *stream,
    candidate_t *remote, uint8_t **password);

uint32_t peer_reflexive_candidate_priority(agent_t *agent,
    candidate_t *local_candidate);

unsigned int 
priv_compute_conncheck_timer(agent_t *agent,
    stream_t *stream);

void 
conn_check_prune_stream(agent_t *agent, stream_t *stream);

void
conn_check_free(agent_t *agent);

#ifdef __cplusplus
}
#endif

#endif //_CONNCHECK_H_


