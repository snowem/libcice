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

#ifndef _ICE_DISCOVERY_H_
#define _ICE_DISCOVERY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "candidate.h"
#include "list.h"
#include "stun/stunagent.h"
#include "stun/usages/timer.h"
#include "types.h"

typedef enum {
  HOST_CANDIDATE_SUCCESS,
  HOST_CANDIDATE_FAILED,
  HOST_CANDIDATE_CANT_CREATE_SOCKET,
  HOST_CANDIDATE_REDUNDANT
} HostCandidateResult;

struct _candidate_discovery
{
  struct list_head list;
  agent_t *agent;         /* back pointer to owner */
  IceCandidateType type;   /* candidate type STUN or TURN */
  socket_t *nicesock;     /* XXX: should be taken from local cand: existing socket to use */
  address_t server;       /* STUN/TURN server address */
  struct timeval next_tick;       /* next tick timestamp */
  int pending;         /* is discovery in progress? */
  int done;            /* is discovery complete? */
  stream_t *stream;
  component_t *component;
  StunAgent stun_agent;
  StunTimer timer;
  uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE_IPV6];
  StunMessage stun_message;
  uint8_t stun_resp_buffer[STUN_MAX_MESSAGE_SIZE];
  StunMessage stun_resp_msg;
//  TurnServer *turn;
};

struct _candidate_refresh
{
  struct list_head list;
  agent_t *agent;         /* back pointer to owner */
  socket_t *nicesock;     /* existing socket to use */
  address_t server;       /* STUN/TURN server address */
  candidate_t *candidate; /* candidate to refresh */
  stream_t *stream;
  component_t *component;
  StunAgent stun_agent;
//  GSource *timer_source;
//  GSource *tick_source;
  StunTimer timer;
  uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE_IPV6];
  StunMessage stun_message;
  uint8_t stun_resp_buffer[STUN_MAX_MESSAGE_SIZE];
  StunMessage stun_resp_msg;
};

HostCandidateResult 
discovery_add_local_host_candidate (
  agent_t *agent, uint32_t stream_id, uint32_t component_id,
  address_t *address, IceCandidateTransport transport,
  candidate_t **outcandidate);


candidate_t *discovery_learn_remote_peer_reflexive_candidate(
  agent_t *agent, stream_t *stream, component_t *component,
  uint32_t priority, const address_t *remote_address,
  socket_t *nicesock, candidate_t *local, candidate_t *remote);

candidate_t*
discovery_add_peer_reflexive_candidate( agent_t *agent, 
  uint32_t stream_id, uint32_t component_id, 
  address_t *address, socket_t *base_socket,
  candidate_t *local, candidate_t *remote);

candidate_t*
discovery_add_server_reflexive_candidate(
  agent_t *agent, uint32_t stream_id, uint32_t component_id,
  address_t *address, IceCandidateTransport transport,
  socket_t *base_socket, int nat_assisted);

void
discovery_discover_tcp_server_reflexive_candidates (
  agent_t *agent, uint32_t stream_id, uint32_t component_id,
  address_t *address, socket_t *base_socket);

void
discovery_prune_stream(agent_t *agent, uint32_t stream_id);

void
refresh_prune_stream(agent_t *agent, uint32_t stream_id);

void
discovery_free(agent_t *agent);

void
refresh_free(agent_t *agent);

#ifdef __cplusplus
}
#endif

#endif //_DISCOVERY_H_







