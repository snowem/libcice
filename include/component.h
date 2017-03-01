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


#ifndef _COMPONENT_H_
#define _COMPONENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "list.h"
#include "types.h"
#include "candidate.h"
#include "stun/stunagent.h"
#include "stun/usages/timer.h"

typedef enum
{
  ICE_COMPONENT_TYPE_RTP = 1,
  ICE_COMPONENT_TYPE_RTCP = 2
} IceComponentType;


typedef enum
{
  ICE_COMPONENT_STATE_DISCONNECTED, // No activity scheduled
  ICE_COMPONENT_STATE_GATHERING,    // Gathering local candidates
  ICE_COMPONENT_STATE_CONNECTING,   // Establishing connectivity
  ICE_COMPONENT_STATE_CONNECTED,    // At least one working candidate pair
  ICE_COMPONENT_STATE_READY,        // ICE concluded, candidate pair selection is now final
  ICE_COMPONENT_STATE_FAILED,       // Connectivity checks have been completed,
                                    //      but connectivity was not established
  ICE_COMPONENT_STATE_LAST          // Dummy state
} IceComponentState;

struct _candidate_pair_keepalive
{
  agent_t *agent;
  uint32_t stream_id;
  uint32_t component_id;
  StunTimer timer;
  uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE_IPV6];
  StunMessage stun_message;
  /*GSource *tick_source;*/
};


struct _candidate_pair
{
  candidate_t *local;
  candidate_t *remote;
  uint64_t priority;           /* candidate pair priority */
  candidate_pair_keepalive_t keepalive;
};

struct _incoming_check
{
  struct list_head list;
  address_t from;
  socket_t *local_socket;
  uint32_t priority;
  int use_candidate;
  uint8_t *username;
  uint16_t username_len;
};

struct _component
{
  struct list_head list;

  uint32_t id;                     /* component id */
  IceComponentType type;
  IceComponentState state;
  candidate_t local_candidates;    /* list of candidate_t objs */
  candidate_t remote_candidates;   /* list of candidate_t objs */
  candidate_t *restart_candidate;  /* for storing active remote candidate during a restart */
  candidate_pair_t selected_pair;  /* independent from checklists, 
                   				        see ICE 11.1. "Sending Media" (ID-19) */

  void *tcp;                       /* pointer to PseudoTcpSocket */
  void *agent;                     /* pointer to agent_t */
  stream_t *stream;

  agent_recv_func  io_callback;    /* function called on io cb */
  void            *io_data;        /* data passed to the io function */

  struct stun_agent_t  stun_agent; /* This stun agent is used to validate all stun requests */

  uint16_t min_port;
  uint16_t max_port;

  incoming_check_t incoming_checks; /* list of IncomingCheck objs */
};

component_t *
component_new (agent_t *agent, stream_t *stream, uint32_t id);

void
component_set_io_callback (component_t *component, agent_recv_func cb, 
   void *user_data);

void
component_attach_socket (component_t *component, socket_t *nicesock);

candidate_t *
component_find_remote_candidate(const component_t *component, 
   const address_t *addr, IceCandidateTransport transport);


void 
component_update_selected_pair (component_t *component, const candidate_pair_t *pair);

int
component_find_pair(component_t *cmp, agent_t *agent, const char *lfoundation, 
   const char *rfoundation, candidate_pair_t *pair);

candidate_t *
component_set_selected_remote_candidate(agent_t *agent, 
       component_t *component, candidate_t *candidate);

void
incoming_check_free(incoming_check_t *icheck);

#ifdef __cplusplus
}
#endif

#endif //_COMPONENT_H_




