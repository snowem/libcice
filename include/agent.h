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

#ifndef _ICE_AGENT_H_
#define _ICE_AGENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/time.h>

#include <event2/event.h>

#include "list.h"
#include "types.h"
#include "stream.h"
#include "discovery.h"
#include "stun/usages/ice.h"

/* XXX: starting from ICE ID-18, Ta SHOULD now be set according
 *      to session bandwidth -> this is not yet implemented in NICE */

#define ICE_AGENT_TIMER_TA_DEFAULT 20      /* timer Ta, msecs (impl. defined) */
//#define ICE_AGENT_TIMER_TR_DEFAULT 25000   /* timer Tr, msecs (impl. defined) */
#define ICE_AGENT_TIMER_TR_DEFAULT 25      /* timer Tr, secs (impl. defined) */
#define ICE_AGENT_TIMER_TR_MIN     15000   /* timer Tr, msecs (ICE ID-19) */
#define ICE_AGENT_MAX_CONNECTIVITY_CHECKS_DEFAULT 100 /* see spec 5.7.3 (ID-19) */


/* An upper limit to size of STUN packets handled (based on Ethernet
 * MTU and estimated typical sizes of ICE STUN packet */
#define MAX_STUN_DATAGRAM_PAYLOAD    1300


typedef enum
{
  ICE_COMPATIBILITY_RFC5245 = 0,
  ICE_COMPATIBILITY_DRAFT19 = ICE_COMPATIBILITY_RFC5245,
  ICE_COMPATIBILITY_GOOGLE,
  ICE_COMPATIBILITY_MSN,
  ICE_COMPATIBILITY_WLM2009,
  ICE_COMPATIBILITY_OC2007,
  ICE_COMPATIBILITY_OC2007R2,
  ICE_COMPATIBILITY_LAST = ICE_COMPATIBILITY_OC2007R2,
} IceCompatibility;



typedef void (*candidate_gathering_done_func)(agent_t *agent, uint32_t stream_id, void *data);
typedef void (*component_state_changed_func)(agent_t *agent, uint32_t stream_id, 
                 uint32_t component_id, uint32_t state, void *data);
typedef void (*new_selected_pair_func)(agent_t *agent, uint32_t _stream_id, 
                 uint32_t component_id, char *lfoundation, char *rfoundation, void *data);
typedef void (*new_remote_candidate_func)(agent_t *agent, uint32_t stream_id, 
                 uint32_t component_id, char *foundation, void *ice);

struct _agent
{
  struct timeval   next_check_tv;        /* property: next conncheck timestamp */
  char     *stun_server_ip;       /* property: STUN server IP */
  uint16_t  stun_server_port;     /* property: STUN server port */
  char     *proxy_ip;             /* property: Proxy server IP */
  uint16_t  proxy_port;           /* property: Proxy server port */
  uint32_t  timer_ta;             /* property: timer Ta */
  uint32_t  max_conn_checks;      /* property: max connectivity checks */

  address_t local_addresses;                    /* list of NiceAddress for local interfaces */
  stream_t  streams;                            /* list of Stream objects */
  candidate_discovery_t discovery_list;         /* list of CandidateDiscovery items */
  candidate_refresh_t   refresh_list;           /* list of CandidateRefresh items */

  uint32_t next_candidate_id;        /* id of next created candidate */
  uint32_t next_stream_id;           /* id of next created candidate */
  uint32_t discovery_unsched_items;  /* number of discovery items unscheduled */

  uint64_t tie_breaker;            /* tie breaker (ICE sect 5.2 "Determining Role" ID-19) */
  IceCompatibility compatibility;  /* property: Compatibility mode */

  char *software_attribute;      /* SOFTWARE attribute */
  /* boolean properties */
  int8_t media_after_tick;       /* Received media after keepalive tick */
  int8_t reliable;               /* property: reliable */
  int8_t keepalive_conncheck;    /* property: keepalive_conncheck */
  int8_t full_mode;              /* property: full-mode */
  int8_t controlling_mode;       /* property: controlling-mode */
  int8_t use_ice_udp;
  int8_t use_ice_tcp;
  
  struct event_base *base;
  //NiceRNG *rng;                   /* FIXME: random number generator */
  //GQueue pending_signals;         /* FIXME: */
 
  struct event *discovery_timer_ev; /* discovery timer event */
  struct event *conncheck_timer_ev; /* conncheck timer event */
  struct event *keepalive_timer_ev; /* keepalive timer event */
  
  // callbacks 
  candidate_gathering_done_func candidate_gathering_done_cb;
  component_state_changed_func  component_state_changed_cb;
  new_selected_pair_func        new_selected_pair_cb;
  new_remote_candidate_func     new_remote_candidate_cb;
  void *candidate_gathering_done_data;
  void *component_state_changed_data;
  void *new_selected_pair_data;
  void *new_remote_candidate_data;

  uint16_t rfc4571_expecting_length;
};

int
ice_init();

agent_t*
ice_agent_new(struct event_base *base, IceCompatibility compat, int control_mode);

int
ice_agent_add_stream (agent_t *agent, uint32_t n_components);

int
ice_agent_set_stream_name (agent_t *agent, uint32_t stream_id, const char *name);

int 
ice_agent_attach_recv (agent_t *agent, uint32_t stream_id, uint32_t component_id,
  agent_recv_func func, void *data);

int
ice_agent_gather_candidates (agent_t *agent, uint32_t stream_id);

void
ice_set_candidate_gathering_done_cb(agent_t *agent, candidate_gathering_done_func cb, void *data);

void
ice_set_component_state_changed_cb(agent_t *agent, component_state_changed_func cb, void *data);

void
ice_set_new_selected_pair_cb(agent_t *agent, new_selected_pair_func cb, void *data);

void
ice_set_new_remote_candidate_cb(agent_t *agent, new_remote_candidate_func cb, void *data);

void
ice_agent_init_stun_agent (agent_t *agent, struct stun_agent_t *stun_agent);

int
ice_agent_add_local_address (agent_t *agent, address_t *addr);

int
agent_find_component(agent_t *agent, uint32_t stream_id, uint32_t component_id,
  stream_t **stream, component_t **component);

stream_t *
agent_find_stream(agent_t *agent, uint32_t stream_id);

uint64_t
agent_candidate_pair_priority(agent_t *agent, candidate_t *local, candidate_t *remote);

int
ice_agent_get_selected_pair (agent_t *agent, uint32_t stream_id,
    uint32_t component_id, candidate_t **local, candidate_t **remote);

int
ice_agent_get_local_credentials ( agent_t *agent, uint32_t stream_id, 
                 char **ufrag, char **pwd);

candidate_t*
ice_agent_get_local_candidates ( agent_t *agent, uint32_t stream_id, uint32_t component_id);

int
ice_agent_set_remote_credentials(agent_t *agent, uint32_t stream_id, 
            const char *ufrag, const char *pwd);

int
ice_agent_set_remote_candidates(agent_t *agent, uint32_t stream_id, 
   uint32_t component_id, const candidate_t *candidates);

void agent_signal_component_state_change(agent_t *agent, 
     uint32_t stream_id, uint32_t component_id, IceComponentState state);

void 
agent_signal_new_selected_pair (agent_t *agent, uint32_t stream_id,
    uint32_t component_id, candidate_t *lcandidate, candidate_t *rcandidate);

int
agent_socket_send(socket_t *sock, const address_t *addr, 
                const char *buf, uint32_t len);

StunUsageIceCompatibility
agent_to_ice_compatibility (agent_t *agent);

void agent_signal_initial_binding_request_received(agent_t *agent, stream_t *stream);

void agent_signal_new_candidate(agent_t *agent, candidate_t *candidate);

void agent_signal_new_remote_candidate (agent_t *agent, candidate_t *candidate);

void agent_timeout_add_with_context (agent_t *agent, void **out,
    const char *name, uint32_t interval, void* func, void* data);

int
ice_agent_send(agent_t *agent, uint32_t stream_id, uint32_t component_id,
  const char *buf, uint32_t len);

int
ice_agent_set_relay_info(agent_t *agent, uint32_t stream_id, 
    uint32_t component_id, const char *server_ip, uint32_t server_port, 
    const char *username, const char *password, IceRelayType type);

void
ice_agent_set_port_range(agent_t *agent, uint32_t stream_id, uint32_t component_id,
    uint32_t min_port, uint32_t max_port);


void
ice_agent_remove_stream(agent_t *agent, uint32_t stream_id);

int
ice_agent_set_selected_remote_candidate( agent_t *agent, uint32_t stream_id, 
           uint32_t component_id, candidate_t *candidate);

candidate_t*
ice_agent_get_remote_candidates(agent_t *agent, uint32_t stream_id, uint32_t component_id);

#ifdef __cplusplus
}
#endif

#endif // _AGENT_H_













