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


#include <sys/time.h>

#include "cice/agent.h"
#include "cice/base64.h"
#include "cice/component.h"
#include "cice/conncheck.h"
#include "cice/network.h"
#include "cice/types.h"
#include "cice/utils.h"

#include "cice/stun/usages/bind.h"
#include "cice/stun/usages/timer.h"
#include "cice/stun/usages/turn.h"

static int 
priv_timer_expired (struct timeval *timer, struct timeval *now)
{
  return (now->tv_sec == timer->tv_sec) ?
    now->tv_usec >= timer->tv_usec :
    now->tv_sec >= timer->tv_sec;
}

/*
 * Sends a connectivity check over candidate pair 'pair'.
 *
 * @return zero on success, non-zero on error
 */
int conn_check_send(agent_t *agent, candidate_check_pair_t *pair)
{

  /* note: following information is supplied:
   *  - username (for USERNAME attribute)
   *  - password (for MESSAGE-INTEGRITY)
   *  - priority (for PRIORITY)
   *  - ICE-CONTROLLED/ICE-CONTROLLING (for role conflicts)
   *  - USE-CANDIDATE (if sent by the controlling agent)
   */

  uint8_t uname[ICE_STREAM_MAX_UNAME] = {0};
  uint8_t *password = NULL;
  stream_t *stream;
  component_t *component;
  uint32_t priority;
  uint32_t uname_len;
  size_t password_len;
  uint32_t buffer_len;
  int controlling = agent->controlling_mode;
  int cand_use = controlling;
  unsigned int timeout;

  if ( agent == NULL || pair == NULL )
     return ICE_ERR;

  ICE_DEBUG("conn_check_send, controlling=%u",controlling);

  if (agent_find_component (agent, pair->stream_id, pair->component_id,
          &stream, &component) != ICE_OK)
    return ICE_ERR;

  uname_len = priv_create_username(agent, stream, pair->component_id,
      pair->remote, pair->local, uname, sizeof (uname), 0);
  password_len = priv_get_password(agent, stream, pair->remote, &password);

  priority = peer_reflexive_candidate_priority(agent, pair->local);

  if (password != NULL &&
      (agent->compatibility == ICE_COMPATIBILITY_MSN ||
       agent->compatibility == ICE_COMPATIBILITY_OC2007)) {
    password = base64_decode ((const unsigned char *)password,password_len,&password_len);
  }

  {
    char tmpbuf[INET6_ADDRSTRLEN];
    char tmpbuf1[INET6_ADDRSTRLEN];
    address_to_string (&pair->remote->addr, tmpbuf);
    address_to_string (&pair->local->addr, tmpbuf1);
    ICE_DEBUG("stun request, agent=%p,localaddr=%s, port=%u, remoteaddr=%s, port=%u, fd=%u, "
        "foundation=%s ,cid=%u, tie=%llu, username=%s(%u), "
        "password=%s(%lu), priority=%u", agent, 
        tmpbuf1, address_get_port (&pair->local->addr),
        tmpbuf, address_get_port (&pair->remote->addr),
        pair->sockptr->fd,
	     pair->foundation, pair->component_id,
	     (unsigned long long)agent->tie_breaker,
        uname, uname_len, password, password_len,
        priority);


  }

  if (cand_use) {
     ICE_DEBUG("set pair nominated, pair=%p",pair);
     pair->nominated = controlling;
  }

  if (uname_len > 0) {
    buffer_len = stun_usage_ice_conncheck_create(&component->stun_agent,
        &pair->stun_message, pair->stun_buffer, sizeof(pair->stun_buffer),
        uname, uname_len, password, password_len,
        cand_use, controlling, priority,
        agent->tie_breaker,
        pair->local->foundation,
        agent_to_ice_compatibility (agent));

    ICE_HEXDUMP(pair->stun_buffer, buffer_len,"stun");

    ICE_DEBUG("conncheck created, agent=%p, bufflen=%d, buff=%p", 
          agent, buffer_len, pair->stun_message.buffer);

    if (agent->compatibility == ICE_COMPATIBILITY_MSN ||
        agent->compatibility == ICE_COMPATIBILITY_OC2007) {
      free(password);
    }

    if (buffer_len > 0) {
      ICE_DEBUG("FIXME: socket reliable, bufflen=%u",buffer_len);
      //if (nice_socket_is_reliable(pair->sockptr)) {
      //  stun_timer_start_reliable(&pair->timer, STUN_TIMER_DEFAULT_RELIABLE_TIMEOUT);
      //} else {
        stun_timer_start(&pair->timer,
            priv_compute_conncheck_timer(agent, stream),
            STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
      //}

      /* TCP-ACTIVE candidate must create a new socket before sending
       * by connecting to the peer. The new socket is stored in the candidate
       * check pair, until we discover a new local peer reflexive */
      ICE_DEBUG("pair info, fd=%d, transport=%u",pair->sockptr->fd,pair->local->transport);
      if (pair->sockptr->fd == 0 && pair->local->transport == ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE) {
        stream_t *stream2 = NULL;
        component_t *component2 = NULL;
        //socket_t *new_socket;

        if (agent_find_component(agent, pair->stream_id, pair->component_id,
                &stream2, &component2) == ICE_OK) {
          ICE_DEBUG("FIXME: create socket reliable");
          /*new_socket = nice_tcp_active_socket_connect (pair->sockptr,
              &pair->remote->addr);
          if (new_socket) {
            pair->sockptr = new_socket;
            _priv_set_socket_tos (agent, pair->sockptr, stream2->tos);
            component_attach_socket (component2, new_socket);
          }*/
        }
      }
      /* send the conncheck */
      ICE_DEBUG("sending conncheck, buf=%p,bufflen=%u",pair->stun_buffer,buffer_len);
      agent_socket_send(pair->sockptr, &pair->remote->addr,
          (const char *)pair->stun_buffer, buffer_len);

      timeout = stun_timer_remainder(&pair->timer);
      /* note: convert from milli to microseconds for g_time_val_add() */
      ICE_DEBUG("set timeout, timeout=%u",timeout);
      gettimeofday(&pair->next_tick,NULL);
      print_timeval(&pair->next_tick); 
      add_microseconds_to_timeval(&pair->next_tick, timeout * 1000);
      print_timeval(&pair->next_tick); 

      /*g_get_current_time (&pair->next_tick);
      g_time_val_add (&pair->next_tick, timeout * 1000);*/
    } else {
      ICE_DEBUG("Agent %p: buffer is empty, cancelling conncheck", agent);
      pair->stun_message.buffer = NULL;
      pair->stun_message.buffer_len = 0;
      return -1;
    }
  } else {
      ICE_DEBUG("Agent %p: no credentials found, cancelling conncheck", agent);
      pair->stun_message.buffer = NULL;
      pair->stun_message.buffer_len = 0;
      return -1;
  }

  return 0;
}


/*
 * Initiates a new connectivity check for a ICE candidate pair.
 *
 * @return TRUE on success, FALSE on error
 */
static int 
priv_conn_check_initiate(agent_t *agent, candidate_check_pair_t *pair)
{
  /* XXX: from ID-16 onwards, the checks should not be sent
   * immediately, but be put into the "triggered queue",
   * see  "7.2.1.4 Triggered Checks"
   */
  gettimeofday(&pair->next_tick,NULL);
  add_microseconds_to_timeval(&pair->next_tick, agent->timer_ta * 1000);
  pair->state = ICE_CHECK_IN_PROGRESS;

  ICE_DEBUG("Agent %p : pair %p state IN_PROGRESS", agent, pair);

  conn_check_send(agent, pair);
  return ICE_OK;
}


/*
 * Fills 'dest' with a username string for use in an outbound connectivity
 * checks. No more than 'dest_len' characters (including terminating
 * NULL) is ever written to the 'dest'.
 */
static
size_t priv_gen_username(agent_t *agent, uint32_t component_id,
    char *remote, char *local, uint8_t *dest, uint32_t dest_len)
{
  uint32_t len = 0; 
  size_t remote_len = strlen(remote);
  size_t local_len = strlen(local);

  if (remote_len > 0 && local_len > 0) { 
    if (agent->compatibility == ICE_COMPATIBILITY_RFC5245 &&
        dest_len >= remote_len + local_len + 1) { 
      memcpy (dest, remote, remote_len);
      len += remote_len;
      memcpy (dest + len, ":", 1);
      len++;
      memcpy (dest + len, local, local_len);
      len += local_len;
    } else if ((agent->compatibility == ICE_COMPATIBILITY_WLM2009 ||
        agent->compatibility == ICE_COMPATIBILITY_OC2007R2) &&
        dest_len >= remote_len + local_len + 4 ) {
      memcpy (dest, remote, remote_len);
      len += remote_len;
      memcpy (dest + len, ":", 1);
      len++;
      memcpy (dest + len, local, local_len);
      len += local_len;
      if (len % 4 != 0) { 
        memset (dest + len, 0, 4 - (len % 4)); 
        len += 4 - (len % 4);
      }
    } else if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE &&
        dest_len >= remote_len + local_len) {
      memcpy (dest, remote, remote_len);
      len += remote_len;
      memcpy (dest + len, local, local_len);
      len += local_len;
    } else if (agent->compatibility == ICE_COMPATIBILITY_MSN ||
          agent->compatibility == ICE_COMPATIBILITY_OC2007) {
      char component_str[10];
      unsigned char *local_decoded = NULL;
      unsigned char *remote_decoded = NULL;
      size_t local_decoded_len;
      size_t remote_decoded_len;
      size_t total_len;
      int padding;

      snprintf(component_str, sizeof(component_str), "%d", component_id);
      local_decoded = base64_decode((const unsigned char *)local,local_len,&local_decoded_len);
      remote_decoded = base64_decode((const unsigned char *)remote,remote_len,&remote_decoded_len);

      total_len = remote_decoded_len + local_decoded_len + 3 + 2*strlen (component_str);
      padding = 4 - (total_len % 4);

      if (dest_len >= total_len + padding) {
        unsigned char pad_char[1] = {0};
        int i;

        memcpy (dest, remote_decoded, remote_decoded_len);
        len += remote_decoded_len;
        memcpy (dest + len, ":", 1);
        len++;
        memcpy (dest + len, component_str, strlen(component_str));
        len += strlen (component_str);

        memcpy (dest + len, ":", 1);
        len++;

        memcpy (dest + len, local_decoded, local_decoded_len);
        len += local_decoded_len;
        memcpy (dest + len, ":", 1);
        len++;
        memcpy (dest + len, component_str, strlen(component_str));;
        len += strlen (component_str);

        for (i = 0; i < padding; i++) {
          memcpy (dest + len, pad_char, 1);
          len++;
        }

      }

      free(local_decoded);
      free(remote_decoded);
    }
  }

  return len;
}

/*
 * Fills 'dest' with a username string for use in an outbound connectivity
 * checks. No more than 'dest_len' characters (including terminating
 * NULL) is ever written to the 'dest'.
 */
size_t priv_create_username(agent_t *agent, stream_t *stream,
    uint32_t component_id, candidate_t *remote, candidate_t *local,
    uint8_t *dest, uint32_t dest_len, int inbound)
{
   ICE_DEBUG("FIXME: priv_create_username");

  char *local_username = NULL;
  char *remote_username = NULL;


  if (remote && remote->username) {
    remote_username = remote->username;
  }

  if (local && local->username) {
    local_username = local->username;
  }

  if (stream) {
    if (remote_username == NULL) {
      remote_username = stream->remote_ufrag;
    }
    if (local_username == NULL) {
      local_username = stream->local_ufrag;
    }
  }

  if (local_username && remote_username) {
    if (inbound) {
      return priv_gen_username(agent, component_id,
          local_username, remote_username, dest, dest_len);
    } else {
      return priv_gen_username(agent, component_id,
          remote_username, local_username, dest, dest_len);
    }
  }

  return 0;
}

void
print_list(candidate_check_pair_head_t *head) {
   candidate_check_pair_t *p = NULL;

   if (!head) return;

   TAILQ_FOREACH(p,head,list) {
      ICE_ERROR("pair info, priority=%lu,foundation=%s:%s (%p)",
            p->priority,p->local->foundation,p->remote->foundation, p->remote);
   }
   return;
}

/*
 * Enforces the upper limit for connectivity checks as described
 * in ICE spec section 5.7.3 (ID-19). See also 
 * conn_check_add_for_candidate().
 */
static void
priv_limit_conn_check_list_size(candidate_check_pair_head_t *conncheck_list, uint32_t upper_limit)
{
  uint32_t valid = 0;
  uint32_t cancelled = 0;
  candidate_check_pair_t *pair = NULL;

  TAILQ_FOREACH(pair,conncheck_list,list) {
     if (pair->state != ICE_CHECK_CANCELLED) {
        valid++;
        if (valid > upper_limit) {
           pair->state = ICE_CHECK_CANCELLED;
           cancelled++;
        }
     }
  }

  if (cancelled > 0) {
    ICE_DEBUG("Agent : Pruned %d candidates. Conncheck list has %d elements"
        " left. Maximum connchecks allowed : %d", cancelled, valid, upper_limit);
  }

  return;
}

static void
conn_check_insert(candidate_check_pair_head_t *head, candidate_check_pair_t *pair) {
  candidate_check_pair_t *a = NULL;

  if (!head || !pair)
    return;

  if (TAILQ_EMPTY(head)) {
    TAILQ_INSERT_HEAD(head,pair,list);
    return;
  }

  TAILQ_FOREACH(a,head,list) {
    if (a->priority > pair->priority) {
      TAILQ_INSERT_BEFORE(a,pair,list);
      break;
    }
  }

  return;
}

/*
 * Creates a new connectivity check pair and adds it to
 * the agent's list of checks.
 */
static void priv_add_new_check_pair (agent_t *agent, uint32_t stream_id, component_t *component, 
    candidate_t *local, candidate_t *remote, IceCheckState initial_state, int use_candidate)
{
  stream_t *stream;
  candidate_check_pair_t *pair;

  if ( local == NULL || remote == NULL )
     return;

  stream = agent_find_stream(agent, stream_id);
  if ( stream == NULL )
     return;

  pair = ICE_MALLOC(candidate_check_pair_t);
  ICE_MEMZERO(pair,candidate_check_pair_t);

  pair->agent = agent;
  pair->stream_id = stream_id;
  pair->component_id = component->id;;
  pair->local = local;
  pair->remote = remote;
  if (remote->type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE)
    pair->sockptr = (socket_t*) remote->sockptr;
  else
    pair->sockptr = (socket_t*) local->sockptr;

  snprintf(pair->foundation, ICE_CANDIDATE_PAIR_MAX_FOUNDATION, 
          "%s:%s", local->foundation, remote->foundation);

  pair->priority = agent_candidate_pair_priority(agent, local, remote);
  pair->state = initial_state;
  pair->nominated = use_candidate;
  pair->controlling = agent->controlling_mode;
  
  ICE_DEBUG("creating new pair, pair=%p, prio=%lu, rfoundation=%s(%p), state=%d", 
            pair, pair->priority, remote->foundation,remote, initial_state);

  conn_check_insert(&stream->connchecks,pair);

  //ICE_DEBUG("conncheck info, size=%u", list_size(&stream->connchecks.list));
  //XXX: modify connchecks list inside list_for_each? check function 'conn_check_remote_candidates_set'
  
  ICE_DEBUG("added a new conncheck, agent=%p, pair=%p, foundation=%s, nominated=%u, stream_id=%u", 
         agent, pair, pair->foundation, pair->nominated, stream_id);
  print_candidate(local,"local");
  print_candidate(remote,"remote");

  /* implement the hard upper limit for number of
     checks (see sect 5.7.3 ICE ID-19): */
  if (agent->compatibility == ICE_COMPATIBILITY_RFC5245) {
    priv_limit_conn_check_list_size(&stream->connchecks, agent->max_conn_checks);
  }

  return;
}


IceCandidateTransport
conn_check_match_transport(IceCandidateTransport transport)
{
  switch (transport) {
    case ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
      return ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
      break;
    case ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
      return ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
      break;
    case ICE_CANDIDATE_TRANSPORT_TCP_SO:
    case ICE_CANDIDATE_TRANSPORT_UDP:
    default:
      return transport;
      break;
  }
  return transport;
}

static void priv_conn_check_add_for_candidate_pair_matched(agent_t *agent,
    uint32_t stream_id, component_t *component, candidate_t *local,
    candidate_t *remote, IceCheckState initial_state)
{
  ICE_DEBUG("Adding check pair, agent=%p, local=%s, ltranpsort=%u, remote=%s(%p), rtransport=%u", 
        agent, local->foundation, local->transport, remote->foundation, remote, remote->transport);

  priv_add_new_check_pair(agent, stream_id, component, local, remote, initial_state, 0);
  if (component->state == ICE_COMPONENT_STATE_CONNECTED ||
      component->state == ICE_COMPONENT_STATE_READY) {
     agent_signal_component_state_change (agent,
        stream_id, component->id, ICE_COMPONENT_STATE_CONNECTED);
  } else {
     agent_signal_component_state_change (agent,
        stream_id, component->id, ICE_COMPONENT_STATE_CONNECTING);
  }

  return;
}

int
conn_check_add_for_candidate_pair(agent_t *agent,
    uint32_t stream_id, component_t *component, 
    candidate_t *local, candidate_t *remote)
{
  int ret = ICE_OK;

  if ( local == NULL || remote == NULL )
     return ICE_ERR;

  /* note: do not create pairs where the local candidate is
   *       a srv-reflexive (ICE 5.7.3. "Pruning the pairs" ID-9) */
  if ((agent->compatibility == ICE_COMPATIBILITY_RFC5245 ||
      agent->compatibility == ICE_COMPATIBILITY_WLM2009 ||
      agent->compatibility == ICE_COMPATIBILITY_OC2007R2) &&
      local->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
    return ICE_ERR;
  }

  /* note: do not create pairs where local candidate has TCP passive transport
   *       (ice-tcp-13 6.2. "Forming the Check Lists") */
  if (local->transport == ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE) {
    return ICE_ERR;
  }

  /* note: match pairs only if transport and address family are the same */
  if (local->transport == conn_check_match_transport (remote->transport) &&
     local->addr.s.addr.sa_family == remote->addr.s.addr.sa_family) {
    priv_conn_check_add_for_candidate_pair_matched(agent, stream_id, component,
        local, remote, ICE_CHECK_FROZEN);
    ret = ICE_OK;
  }

  return ret;
}

/*
 * Forms new candidate pairs by matching the new remote candidate
 * 'remote_cand' with all existing local candidates of 'component'.
 * Implements the logic described in ICE sect 5.7.1. "Forming Candidate
 * Pairs" (ID-19).
 *
 * @param agent context
 * @param component pointer to the component
 * @param remote remote candidate to match with
 *
 * @return number of checks added, negative on fatal errors
 */
int
conn_check_add_for_candidate(agent_t *agent, uint32_t stream_id, 
      component_t *component, candidate_t *remote)
{
   struct list_head *pos;
   int added = 0;
   int ret = 0;

   if ( remote == NULL || agent == NULL || component == NULL ) {
      ICE_ERROR("null pointers, agent=%p,component=%p,remote=%p",agent,component,remote);
      return ICE_ERR;
   }

   list_for_each(pos,&component->local_candidates.list) {
      candidate_t *local = list_entry(pos,candidate_t,list);
      ret = conn_check_add_for_candidate_pair(agent, stream_id, component, local, remote);
      if (ret == ICE_OK) {
         ++added;
      }
   }

   ICE_DEBUG("candidate info, added=%u, stream_id=%u",added,stream_id);

   return added;
}


int 
conn_check_add_for_local_candidate(agent_t *agent, 
  uint32_t stream_id, component_t *component, candidate_t *local)
{
  struct list_head *pos;
  int added = 0;
  int ret = 0;


  if (local == NULL)
     return 0;
  
  ICE_DEBUG("new candidate pairs, local=%p, added=%d",local, added);

  list_for_each(pos,&component->remote_candidates.list) {
    candidate_t *remote = list_entry(pos,candidate_t,list);
    ICE_ERROR("remote candidate info, stream_id=%d, foundation=%s(%p)",
             stream_id, remote->foundation, remote);
    ret = conn_check_add_for_candidate_pair(agent, stream_id, component, local, remote);
    ICE_DEBUG("check new pair, ret=%d",ret);
    if (ret == ICE_OK) {
      ++added;
    }
  }

  ICE_DEBUG("new candidate pairs, added=%d",added);

  return added;
}

/*
 * Timer callback that handles initiating and managing connectivity
 * checks (paced by the Ta timer).
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static int 
priv_conn_keepalive_tick_unlocked(agent_t *agent)
{
  struct list_head *k;
  int errors = 0;
  int ret = ICE_FALSE;
  size_t buf_len = 0;
  stream_t *stream = NULL;

  //ICE_ERROR("conn keepalive tick, keepalive_conncheck=%u",agent->keepalive_conncheck);
  // case 1: session established and media flowing
  //         (ref ICE sect 10 "Keepalives" ID-19) 
  TAILQ_FOREACH(stream,&agent->streams,list) {
    component_t *component = NULL;
    TAILQ_FOREACH(component,&stream->components,list) {
      if (component->selected_pair.local != NULL) {
	     candidate_pair_t *p = &component->selected_pair;

        // Disable keepalive checks on TCP candidates
        ICE_DEBUG("pair info, pair=%p, local_transport=%u", p, p->local->transport);
        if (p->local->transport != ICE_CANDIDATE_TRANSPORT_UDP)
          continue;

        if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE ||
            agent->keepalive_conncheck) {
          uint32_t priority;
          uint8_t uname[ICE_STREAM_MAX_UNAME];
          size_t uname_len =
              priv_create_username (agent, agent_find_stream (agent, stream->id),
                  component->id, p->remote, p->local, uname, sizeof (uname),
                  ICE_FALSE);
          uint8_t *password = NULL;
          size_t password_len = priv_get_password (agent,
              agent_find_stream (agent, stream->id), p->remote, &password);

          priority = peer_reflexive_candidate_priority (agent, p->local);

          {
            char tmpbuf[INET6_ADDRSTRLEN];
            address_to_string (&p->remote->addr, tmpbuf);
            ICE_ERROR("Agent %p : Keepalive STUN-CC REQ to '%s:%u', "
                "socket=%u (c-id:%u), username='%.*s' (%lu), "
                "password='%.*s' (%lu), priority=%u.", agent,
                tmpbuf, address_get_port (&p->remote->addr),
                ((socket_t *)p->local->sockptr)->fd,
                component->id, (int) uname_len, uname, uname_len,
                (int) password_len, password, password_len, priority);
          }

          if (uname_len > 0) {
            buf_len = stun_usage_ice_conncheck_create (&component->stun_agent,
                &p->keepalive.stun_message, p->keepalive.stun_buffer,
                sizeof(p->keepalive.stun_buffer),
                uname, uname_len, password, password_len,
                agent->controlling_mode, agent->controlling_mode, priority,
                agent->tie_breaker,
                NULL,
                agent_to_ice_compatibility (agent));

            ICE_ERROR("Agent %p: conncheck created %zd - %p",
                agent, buf_len, p->keepalive.stun_message.buffer);

            if (buf_len > 0) {
              stun_timer_start (&p->keepalive.timer, STUN_TIMER_DEFAULT_TIMEOUT,
                  STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);

              agent->media_after_tick = ICE_FALSE;

              // send the conncheck
              ICE_ERROR("conncheck keepalive");
              agent_socket_send((socket_t*)p->local->sockptr, &p->remote->addr,
                  (char *)p->keepalive.stun_buffer, buf_len);

              p->keepalive.stream_id = stream->id;
              p->keepalive.component_id = component->id;
              p->keepalive.agent = agent;

              agent_timeout_add_with_context (p->keepalive.agent,
                  NULL/*&p->keepalive.tick_source*/, "Pair keepalive",
                  stun_timer_remainder (&p->keepalive.timer),
                  NULL/*priv_conn_keepalive_retransmissions_tick*/, p);
            } else {
              ++errors;
            }
          }
        } else {
          buf_len = stun_usage_bind_keepalive (&component->stun_agent,
              &p->keepalive.stun_message, p->keepalive.stun_buffer,
              sizeof(p->keepalive.stun_buffer));

          if (buf_len > 0) {
            agent_socket_send ((socket_t*)p->local->sockptr, &p->remote->addr,
                (char *)p->keepalive.stun_buffer, buf_len);

            ICE_DEBUG("Agent %p : stun_bind_keepalive for pair %p res %d.",
                agent, p, (int) buf_len);
          } else {
            ++errors;
          }
        }
      }
    }
  }

  // case 2: connectivity establishment ongoing
  //         (ref ICE sect 4.1.1.4 "Keeping Candidates Alive" ID-19)
  TAILQ_FOREACH(stream,&agent->streams,list) {
    component_t *component = NULL;
    TAILQ_FOREACH(component,&stream->components,list) {
      if (component->state < ICE_COMPONENT_STATE_READY &&
          agent->stun_server_ip) {
        address_t stun_server;
        if (address_set_from_string (&stun_server, agent->stun_server_ip)) {
          StunAgent stun_agent;
          uint8_t stun_buffer[STUN_MAX_MESSAGE_SIZE_IPV6];
          StunMessage stun_message;
          size_t buffer_len = 0;

          address_set_port (&stun_server, agent->stun_server_port);

          // FIXME: This will cause the stun response to arrive on the socket
          // but the stun agent will not be able to parse it due to an invalid
          // stun message since RFC3489 will not be compatible, and the response
          // will be forwarded to the application as user data
          stun_agent_init (&stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
              STUN_COMPATIBILITY_RFC3489, 0);

          buffer_len = stun_usage_bind_create (&stun_agent,
              &stun_message, stun_buffer, sizeof(stun_buffer));

          list_for_each(k,&component->local_candidates.list) {
            candidate_t *candidate = list_entry(k,candidate_t,list);
            if (candidate->type == ICE_CANDIDATE_TYPE_HOST &&
                candidate->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
              // send the conncheck 
              ICE_DEBUG("Agent %p : resending STUN on %s to keep the "
                  "candidate alive.", agent, candidate->foundation);
              agent_socket_send ((socket_t*)candidate->sockptr, &stun_server,
                  (char *)stun_buffer, buffer_len);
            }
          }
        }
      }
    }
  }

  if (errors) {
    ICE_ERROR("Agent %p : stopping keepalive timer", agent);
    goto done;
  }

  ret = ICE_TRUE;

done:
  return ret;
}


/*
 * Changes the selected pair for the component if 'pair' is nominated
 * and has higher priority than the currently selected pair. See
 * ICE sect 11.1.1. "Procedures for Full Implementations" (ID-19).
 */
static int 
priv_update_selected_pair(agent_t *agent, component_t *component, candidate_check_pair_t *pair)
{
   candidate_pair_t cpair;

   if ( agent == NULL || component == NULL )
      return ICE_ERR;
       
   if (pair->priority > component->selected_pair.priority 
       && component_find_pair(component, agent, pair->local->foundation,
       pair->remote->foundation, &cpair) == ICE_OK ) {
      
      ICE_ERROR("changing SELECTED PAIR for component %u: %s:%s ,prio:%lu", 
                component->id, pair->local->foundation, pair->remote->foundation, pair->priority);
      print_candidate(cpair.local,"local peer");
      print_candidate(cpair.remote,"remote peer");

      component_update_selected_pair(component, &cpair);
      priv_conn_keepalive_tick_unlocked(agent);
      agent_signal_new_selected_pair(agent, pair->stream_id, component->id,
                                     pair->local, pair->remote);

  }

  return ICE_OK;
}

/*
 * Implemented the pruning steps described in ICE sect 8.1.2
 * "Updating States" (ID-19) after a pair has been nominated.
 *
 * @see priv_update_check_list_state_failed_components()
 */
static uint32_t 
priv_prune_pending_checks(stream_t *stream, uint32_t component_id)
{
  uint64_t highest_nominated_priority = 0; 
  uint32_t in_progress = 0; 
  candidate_check_pair_t *p = NULL;

  ICE_DEBUG("Agent XXX: Finding highest priority, component=%d", component_id);

  TAILQ_FOREACH(p,&stream->connchecks,list) {
    if ( p->component_id == component_id && p->nominated == ICE_TRUE &&
         (p->state == ICE_CHECK_SUCCEEDED || p->state == ICE_CHECK_DISCOVERED) ){
      ICE_DEBUG("verify priority, priority=%llu", p->priority);
      if (p->priority > highest_nominated_priority) {
        highest_nominated_priority = p->priority;
      }    
    }    
  }

  ICE_DEBUG("Agent XXX: Pruning pending checks, highest_nominated_priority=%lu", highest_nominated_priority);

  /* step: cancel all FROZEN and WAITING pairs for the component */
  //list_for_each(i,&stream->connchecks.list) {
  //  candidate_check_pair_t *p = list_entry(i,candidate_check_pair_t,list);
  TAILQ_FOREACH(p,&stream->connchecks,list) {
    if (p->component_id == component_id) {
      if (p->state == ICE_CHECK_FROZEN || p->state == ICE_CHECK_WAITING) {
         p->state = ICE_CHECK_CANCELLED;
         ICE_DEBUG("Agent XXX : pair %p state CANCELED", p);
      }

      /* note: a SHOULD level req. in ICE 8.1.2. "Updating States" (ID-19) */
      if (p->state == ICE_CHECK_IN_PROGRESS) {
        if (highest_nominated_priority != 0 &&
            p->priority < highest_nominated_priority) {
          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          p->state = ICE_CHECK_CANCELLED;
          ICE_DEBUG("Agent XXX : pair %p state CANCELED", p);
        } else {
          /* We must keep the higher priority pairs running because if a udp
           * packet was lost, we might end up using a bad candidate */
          ICE_DEBUG("in-progress pair with higher priority, priority=%lu, nominated_pri=%lu"
                , p->priority, highest_nominated_priority);
          in_progress++;
        }
      }
    }
  }

  ICE_DEBUG("Agent XXX: Pruning pending checks, in_progress=%lu", in_progress);
  return in_progress;
}


/*
 * Updates the check list state for a stream component.
 *
 * Implements the algorithm described in ICE sect 8.1.2 
 * "Updating States" (ID-19) as it applies to checks of 
 * a certain component. If there are any nominated pairs, 
 * ICE processing may be concluded, and component state is 
 * changed to READY.
 *
 * Sends a component state changesignal via 'agent'.
 */
static void 
priv_update_check_list_state_for_ready(agent_t *agent, stream_t *stream, component_t *component)
{
   candidate_check_pair_t *p = NULL;
   int succeeded = 0, nominated = 0;


   if ( component == NULL )
      return;
   // step: search for at least one nominated pair
   TAILQ_FOREACH(p,&stream->connchecks,list) {
      ICE_DEBUG("update check list, pair=%p, nominated=%u, state=%u, p-cid=%u, cid=%u, prio=%llu", 
             p, p->nominated, p->state, p->component_id, component->id, p->priority);
      if (p->component_id == component->id) {
         if (p->state == ICE_CHECK_SUCCEEDED ||
             p->state == ICE_CHECK_DISCOVERED) {
	         ++succeeded;
	      if (p->nominated == ICE_TRUE) {
            ++nominated;
         }
      }
    }
  }
  ICE_DEBUG("check ready state, nominated=%u",nominated);
  if (nominated > 0) {
    // Only go to READY if no checks are left in progress. If there are
    // any that are kept, then this function will be called again when the
    // conncheck tick timer finishes them all
    if (priv_prune_pending_checks(stream, component->id) == 0) {
      agent_signal_component_state_change (agent, stream->id,
          component->id, ICE_COMPONENT_STATE_READY);
    }
  }
  ICE_DEBUG("conncheck list status, agent=%p, nominated=%u, succeeded=%u, cid=%u", 
        agent, nominated, succeeded, component->id);


  return;
}


/*
 * The remote party has signalled that the candidate pair
 * described by 'component' and 'remotecand' is nominated
 * for use.
 */
static void 
priv_mark_pair_nominated(agent_t *agent, stream_t *stream, 
  component_t *component, candidate_t *remotecand)
{
   candidate_check_pair_t *pair = NULL;

   if (agent == NULL || stream == NULL || component == NULL )
      return;
   
   /* step: search for at least one nominated pair */
   TAILQ_FOREACH(pair,&stream->connchecks,list) {
      /* XXX: hmm, how to figure out to which local candidate the 
       *      check was sent to? let's mark all matching pairs
       *      as nominated instead */
      ICE_DEBUG("checking pair nominated, foundation=%s,remote=%p,remotecand=%p, prio=%lu", 
                pair->foundation, pair->remote, remotecand, pair->priority);
      //ICE_ERROR("remote cand info, foundation=%s(%p)", pair->remote->foundation, pair->remote);
      if (pair->remote == remotecand) {
         ICE_DEBUG("marking pair as nominated, agent=%p, pair=%p, foundation=%s, state=%u", 
               agent, pair, pair->foundation, pair->state);
         pair->nominated = 1;
         if (pair->state == ICE_CHECK_SUCCEEDED ||
	          pair->state == ICE_CHECK_DISCOVERED) {
	         priv_update_selected_pair(agent, component, pair);
         }
         priv_update_check_list_state_for_ready(agent, stream, component);
      }
   }
   return;
}

/*
 * Schedules a triggered check after a successfully inbound 
 * connectivity check. Implements ICE sect 7.2.1.4 "Triggered Checks" (ID-19).
 * 
 * @param agent self pointer
 * @param component the check is related to
 * @param local_socket socket from which the inbound check was received
 * @param remote_cand remote candidate from which the inbound check was sent
 * @param use_candidate whether the original check had USE-CANDIDATE attribute set
 */
static int 
priv_schedule_triggered_check(agent_t *agent, stream_t *stream, component_t *component, 
    socket_t *local_socket, candidate_t *remote_cand, int use_candidate)
{
  candidate_check_pair_t *p = NULL;
  struct list_head *i;
  candidate_t *local = NULL;

  if ( remote_cand == NULL )
     return ICE_ERR;

  //ICE_DEBUG("trigger check, use_candidate=%u, conncheck_list=%u",
  //          use_candidate, list_size(&stream->connchecks.list));

  //list_for_each(i,&stream->connchecks.list) {
  //    candidate_check_pair_t *p = list_entry(i,candidate_check_pair_t,list);
  TAILQ_FOREACH(p,&stream->connchecks,list) {
      if (p->component_id == component->id && 
          p->remote == remote_cand &&
          ((p->local->transport == ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE &&
              p->sockptr == local_socket) ||
              (p->local->transport != ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE &&
                  p->local->sockptr == local_socket))) {
        /* We don't check for p->sockptr because in the case of
         * tcp-active we don't want to retrigger a check on a pair that
         * was FAILED when a peer-reflexive pair was created */

	     ICE_DEBUG("found a matching pair for triggered check, agent=%p, pair=%p, state=%d", 
               agent, p, p->state);

        print_address(&p->local->addr);
        print_address(&p->remote->addr);
	
	     if (p->state == ICE_CHECK_WAITING ||
	         p->state == ICE_CHECK_FROZEN)
     	    priv_conn_check_initiate(agent, p);
        else if (p->state == ICE_CHECK_IN_PROGRESS) {
	       /* XXX: according to ICE 7.2.1.4 "Triggered Checks" (ID-19),
     	     * we should cancel the existing one, instead we reset our timer, so
	        * we'll resend the exiting transactions faster if needed...? :P
	        */
	       ICE_DEBUG("Agent %p : check already in progress, restarting the timer again?: %s ..", agent,
                 p->timer_restarted ? "no" : "yes");
          /* FIXME: nice_socket_is_reliable */
	       if (/*!nice_socket_is_reliable (p->sockptr) &&*/ !p->timer_restarted) {
	         stun_timer_start (&p->timer, priv_compute_conncheck_timer (agent, stream),
                              STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
	         p->timer_restarted = ICE_TRUE;
	       }
	     }
	     else if (p->state == ICE_CHECK_SUCCEEDED ||
		           p->state == ICE_CHECK_DISCOVERED) {
          ICE_DEBUG("Agent %p : Skipping triggered check, already completed", agent); 
          /* note: this is a bit unsure corner-case -- let's do the
           *   same state update as for processing responses to our own checks */
          priv_update_check_list_state_for_ready (agent, stream, component);

          /* note: to take care of the controlling-controlling case in
           *       aggressive nomination mode, send a new triggered
           *       check to nominate the pair */
	       if ((agent->compatibility == ICE_COMPATIBILITY_RFC5245 ||
               agent->compatibility == ICE_COMPATIBILITY_WLM2009 ||
               agent->compatibility == ICE_COMPATIBILITY_OC2007R2) &&
              agent->controlling_mode)
	         priv_conn_check_initiate (agent, p);
	     } else if (p->state == ICE_CHECK_FAILED) {
          /* 7.2.1.4 Triggered Checks
             If the state of the pair is Failed, it is changed to Waiting
             and the agent MUST create a new connectivity check for that
             pair (representing a new STUN Binding request transaction), by
             enqueueing the pair in the triggered check queue. */
          priv_conn_check_initiate (agent, p);
        }

        /* note: the spec says the we SHOULD retransmit in-progress
         *       checks immediately, but we won't do that now */

	     return ICE_TRUE;
      }
  }

  list_for_each(i,&component->local_candidates.list) {
    local = list_entry(i,candidate_t,list);
    if (local->sockptr == local_socket)
      break;
  }

  if (i) {
    ICE_ERROR("Agent %p : Adding a triggered check to conn.check list (local=%p).", agent, local);
    priv_add_new_check_pair(agent, stream->id, component, 
          local, remote_cand, ICE_CHECK_WAITING, use_candidate);
    return ICE_TRUE;
  }
  else {
    ICE_DEBUG("Agent %p : Didn't find a matching pair for triggered check (remote-cand=%p).", 
           agent, remote_cand);
    return ICE_FALSE;
  }

}



/*
 * Preprocesses a new connectivity check by going through list 
 * of a any stored early incoming connectivity checks from 
 * the remote peer. If a matching incoming check has been already
 * received, update the state of the new outgoing check 'pair'.
 * 
 * @param agent context pointer
 * @param stream which stream (of the agent)
 * @param component pointer to component object to which 'pair'has been added
 * @param pair newly added connectivity check
 */
static void 
priv_preprocess_conn_check_pending_data(agent_t *agent, stream_t *stream, 
     component_t *component, candidate_check_pair_t *pair)
{
   incoming_check_t *icheck = NULL;
   int added = 0;

   TAILQ_FOREACH(icheck,&component->incoming_checks,list) {
      ICE_DEBUG("Checking stored early-icheck, sid=%u, cid=%u, local=%s, remote=%s",
             stream->id, component->id,pair->local->foundation,pair->remote->foundation);
      print_address(&icheck->from);
      print_address(&pair->remote->addr);
      ICE_DEBUG("compare, local_socket=%p, sockptr=%p",icheck->local_socket,pair->sockptr);
      if (address_equal(&icheck->from, &pair->remote->addr) &&
          icheck->local_socket == pair->sockptr) {
         ICE_ERROR("Updating stored early-icheck , agent=%p, pair=%p, check=%p, sid=%u, cid=%u, use_candidate=%u", 
               agent, pair, icheck, stream->id, component->id, icheck->use_candidate);
         if (icheck->use_candidate) {
	         priv_mark_pair_nominated(agent, stream, component, pair->remote);
         }
         priv_schedule_triggered_check(agent, stream, component, icheck->local_socket, pair->remote, icheck->use_candidate);
      }
      added++;
   }

   ICE_DEBUG("pending checks, added=%u",added);

   return;
}

/*
 * Frees the CandidateCheckPair structure pointer to 
 * by 'user data'. Compatible with GDestroyNotify.
 */
static void conn_check_free_item (candidate_check_pair_t *pair)
{
  if ( pair == NULL )
     return;

  ICE_DEBUG("FIXME: free candidate pair, pair=%p",pair);
  //pair->stun_message.buffer = NULL;
  //pair->stun_message.buffer_len = 0;
  //g_slice_free (CandidateCheckPair, pair);
}


static int
prune_cancelled_conn_check(candidate_check_pair_head_t *conncheck_list)
{
   candidate_check_pair_t *pair = NULL;

continue_cancel:
   TAILQ_FOREACH(pair,conncheck_list,list) {
      if (pair->state == ICE_CHECK_CANCELLED) {
         TAILQ_REMOVE(conncheck_list,pair,list);
         conn_check_free_item(pair);
         goto continue_cancel;
      }
   }

  return 0;
}


/*
 * Handle any processing steps for connectivity checks after
 * remote candidates have been set. This function handles
 * the special case where answerer has sent us connectivity
 * checks before the answer (containing candidate information),
 * reaches us. The special case is documented in sect 7.2 
 * if ICE spec (ID-19).
 */
void 
conn_check_remote_candidates_set(agent_t *agent)
{
   struct list_head *l, *m, *n;
   stream_t *stream = NULL;

   TAILQ_FOREACH(stream,&agent->streams,list) {
      candidate_check_pair_t *pair = NULL;
      TAILQ_FOREACH(pair,&stream->connchecks,list) {
         component_t *component = stream_find_component_by_id(stream, pair->component_id);
         incoming_check_t *icheck = NULL;
         int match = 0;

         ICE_DEBUG("stream preprocess, sid=%u,cid=%u,local=%s,remote=%s",
               stream->id,component->id,pair->local->foundation,pair->remote->foundation);

         /* perform delayed processing of spec steps section 7.2.1.4,
          	and section 7.2.1.5 */
         priv_preprocess_conn_check_pending_data(agent, stream, component, pair);

         TAILQ_FOREACH(icheck,&component->incoming_checks,list) {
            /* sect 7.2.1.3., "Learning Peer Reflexive Candidates", has to
             * be handled separately */
            ICE_DEBUG("learning peer reflexive candidate, priority=%u",icheck->priority);
            list_for_each(l,&component->remote_candidates.list) {
               candidate_t *cand = list_entry(l,candidate_t,list);
               print_address(&icheck->from);
               print_address(&cand->addr);
               if (address_equal (&icheck->from, &cand->addr)) {
                  match = 1;
                  break;
               }
            }
            
            ICE_DEBUG("learning peer reflexive candidate, match=%u, priority=%u",match, icheck->priority);
            if (match != 1) {
               /* note: we have gotten an incoming connectivity check from
                *       an address that is not a known remote candidate */

               candidate_t *local_candidate = NULL;
               candidate_t *remote_candidate = NULL;
               
               ICE_DEBUG("agent info, compatibility=%u", agent->compatibility);
               if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE ||
                   agent->compatibility == ICE_COMPATIBILITY_MSN ||
                   agent->compatibility == ICE_COMPATIBILITY_OC2007) {
                  /* We need to find which local candidate was used */
                  uint8_t uname[ICE_STREAM_MAX_UNAME];
                  uint32_t uname_len;

                  ICE_DEBUG("Agent %p: We have a peer-reflexive candidate in a "
                        "stored pending check", agent);

                  list_for_each(m,&component->remote_candidates.list) {
                     list_for_each(n,&component->local_candidates.list) {
                        candidate_t *rcand = list_entry(m,candidate_t,list);
                        candidate_t *lcand = list_entry(n,candidate_t,list);

                        uname_len = priv_create_username(agent, stream,
                                           component->id, rcand, lcand,
                                           uname, sizeof(uname), 1);

                        ICE_DEBUG("pending check, comparing usernames of len %d and %d, equal=%d",
                            icheck->username_len, uname_len,
                            icheck->username && uname_len == icheck->username_len &&
                            memcmp(uname, icheck->username, icheck->username_len) == 0);
                /*stun_ICE_DEBUG_bytes ("  first username:  ",
                    icheck->username,
                    icheck->username? icheck->username_len : 0);
                stun_debug_bytes ("  second username: ", uname, uname_len);*/

                        if (icheck->username &&
                            uname_len == icheck->username_len &&
                            memcmp (uname, icheck->username, icheck->username_len) == 0) {
                          local_candidate = lcand;
                          remote_candidate = rcand;
                          break;
                        }
                     }
                  }
               } else {
                  list_for_each(l,&component->local_candidates.list) {
                      candidate_t *cand = list_entry(l,candidate_t,list);
                      if (address_equal (&cand->addr, &icheck->local_socket->addr)) {
                         local_candidate = cand;
                         break;
                      }
                  }
               }

               if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE && local_candidate == NULL) {
                  /* if we couldn't match the username, then the matching remote
                   * candidate hasn't been received yet.. we must wait */
                  ICE_DEBUG("Agent %p : Username check failed. pending check has "
                         "to wait to be processed", agent);
               } else {
                  candidate_t *candidate = NULL;

                  candidate = discovery_learn_remote_peer_reflexive_candidate (agent,
                                 stream,
                                 component,
                                 icheck->priority,
                                 &icheck->from,
                                 icheck->local_socket,
                                 local_candidate, remote_candidate);
                  if (candidate) {
                     if (local_candidate && local_candidate->transport == ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE) {
                        priv_conn_check_add_for_candidate_pair_matched (agent, stream->id, component, 
                                 local_candidate, candidate, ICE_CHECK_DISCOVERED);
                     } else {
                        conn_check_add_for_candidate (agent, stream->id, component, candidate);
                     }
                     
                     if (icheck->use_candidate)
                        priv_mark_pair_nominated(agent, stream, component, candidate);
                     priv_schedule_triggered_check(agent, stream, component, 
                              icheck->local_socket, candidate, icheck->use_candidate);
                  }
               }
            }
            
         }
         /* Once we process the pending checks, we should free them to avoid
          * reprocessing them again if a dribble-mode set_remote_candidates
          * is called */
         ICE_DEBUG("process the pending checks");
         incoming_check_free(&component->incoming_checks);
         TAILQ_INIT(&component->incoming_checks);
         /*g_slist_free_full (component->incoming_checks, (GDestroyNotify) incoming_check_free);*/
         //component->incoming_checks = NULL;


      } // connchecks
      prune_cancelled_conn_check(&stream->connchecks);
   } // stream list

   return;
}

/*
 * Unfreezes the next connectivity check in the list. Follows the
 * algorithm (2.) defined in 5.7.4 (Computing States) of the ICE spec
 * (ID-19), with some exceptions (see comments in code).
 *
 * See also sect 7.1.2.2.3 (Updating Pair States), and
 * priv_conn_check_unfreeze_related().
 * 
 * @return TRUE on success, and FALSE if no frozen candidates were found.
 */
static int 
priv_conn_check_unfreeze_next(agent_t *agent)
{
  candidate_check_pair_t *pair = NULL;
  stream_t *stream = NULL;

  /* XXX: the unfreezing is implemented a bit differently than in the
   *      current ICE spec, but should still be interoperate:
   *   - checks are not grouped by foundation
   *   - one frozen check is unfrozen (lowest component-id, highest
   *     priority)
   */
  TAILQ_FOREACH(stream,&agent->streams,list) {
    uint64_t max_frozen_priority = 0;
    candidate_check_pair_t *p = NULL;

    TAILQ_FOREACH(p,&stream->connchecks,list) {
      /* XXX: the prio check could be removed as the pairs are sorted
       *       already */
      //ICE_DEBUG("pair info, state=%u,priority=%u",p->state,p->priority);
      if (p->state == ICE_CHECK_FROZEN) {
	      if (p->priority > max_frozen_priority) {
      	  max_frozen_priority = p->priority;
	        pair = p;
      	}
      }
    }

    if (pair) 
      break;
  }
  
  if (pair) {
    ICE_DEBUG("Agent %p : Pair %p with s/c-id %u/%u (%s) unfrozen.", agent, pair, pair->stream_id, pair->component_id, pair->foundation);
    pair->state = ICE_CHECK_WAITING;
    ICE_DEBUG("Agent %p : pair %p state WAITING", agent, pair);
    return ICE_TRUE;
  } else {
    //ICE_DEBUG("Agent %p : failed to set pair state to WAITING", agent);
  }

  return ICE_FALSE;
}

/*
 * Finds the next connectivity check in WAITING state.
 */
static candidate_check_pair_t*
priv_conn_check_find_next_waiting(candidate_check_pair_head_t *conn_check_list)
{
  candidate_check_pair_t *p = NULL;

  /* note: list is sorted in priority order to first waiting check has
   *       the highest priority */
  TAILQ_FOREACH(p,conn_check_list,list) {
    if (p->state == ICE_CHECK_WAITING)
      return p;
  }
  
  ICE_DEBUG("not found next-waiting pair");
  return NULL;
}

/*
 * Returns a password string for use in an outbound connectivity
 * check.
 */
size_t priv_get_password(agent_t *agent, stream_t *stream,
    candidate_t *remote, uint8_t **password)
{
  if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE)
    return 0;

  if (remote && remote->password) {
    *password = (uint8_t *)remote->password;
    return strlen(remote->password);
  }

  if (stream) {
    *password = (uint8_t *)stream->remote_password;
    return strlen(stream->remote_password);
  }

  return 0;
}


uint32_t peer_reflexive_candidate_priority(agent_t *agent,
    candidate_t *local_candidate)
{
  candidate_t *candidate_priority =
      candidate_new(ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
  uint32_t priority;

  candidate_priority->transport = local_candidate->transport;
  candidate_priority->component_id = local_candidate->component_id;
  if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE) {
    priority = candidate_jingle_priority (candidate_priority);
  } else if (agent->compatibility == ICE_COMPATIBILITY_MSN ||
             agent->compatibility == ICE_COMPATIBILITY_OC2007) {
    priority = candidate_msn_priority (candidate_priority);
  } else if (agent->compatibility == ICE_COMPATIBILITY_OC2007R2) {
    priority = candidate_ms_ice_priority (candidate_priority,
        agent->reliable, 0);
  } else {
    priority = candidate_ice_priority (candidate_priority,
        agent->reliable, 0);
  }
  candidate_free(candidate_priority);

  return priority;
}


/* Implement the computation specific in RFC 5245 section 16 */
unsigned int 
priv_compute_conncheck_timer(agent_t *agent,
    stream_t *stream)
{
  uint32_t waiting_and_in_progress = 0; 
  unsigned int rto = 0; 
  candidate_check_pair_t *pair = NULL;

  TAILQ_FOREACH(pair,&stream->connchecks,list) {
    if (pair->state == ICE_CHECK_IN_PROGRESS ||
        pair->state == ICE_CHECK_WAITING)
      waiting_and_in_progress++;
  }

  /* FIXME: This should also be multiple by "N", which I believe is the
   * number of Streams currently in the conncheck state. */
  rto = agent->timer_ta  * waiting_and_in_progress;

  /* We assume non-reliable streams are RTP, so we use 100 as the max */
  if (agent->reliable)
    return ICE_MAX(rto, 500);
  else 
    return ICE_MAX(rto, 100);
}

 
static void
candidate_check_pair_fail(stream_t *stream, agent_t *agent, candidate_check_pair_t *p)
{
  StunTransactionId id;
  component_t *component;

  component = stream_find_component_by_id(stream, p->component_id);

  p->state = ICE_CHECK_FAILED;
  ICE_DEBUG("Agent %p : pair %p state FAILED", agent, p);

  if (p->stun_message.buffer != NULL) {
    stun_message_id(&p->stun_message, id);
    stun_agent_forget_transaction(&component->stun_agent, id);
  }

  p->stun_message.buffer = NULL;
  p->stun_message.buffer_len = 0;
}

/*
 * Helper function for connectivity check timer callback that
 * runs through the stream specific part of the state machine. 
 *
 * @param schedule if TRUE, schedule a new check
 *
 * @return will return FALSE when no more pending timers.
 */
static int 
priv_conn_check_tick_stream(stream_t *stream, agent_t *agent, struct timeval *now)
{
  uint32_t s_inprogress = 0, s_succeeded = 0, s_discovered = 0,
           s_nominated = 0, s_waiting_for_nomination = 0;
  uint32_t frozen = 0, waiting = 0;
  int keep_timer_going = ICE_FALSE;
  candidate_check_pair_t *p = NULL;

  TAILQ_FOREACH(p,&stream->connchecks,list) {
    if (p->state == ICE_CHECK_IN_PROGRESS) {
      if (p->stun_message.buffer == NULL) {
	     ICE_DEBUG("Agent %p : STUN connectivity check was cancelled, marking as done.", agent);
	     p->state = ICE_CHECK_FAILED;
        ICE_DEBUG("Agent %p : pair %p state FAILED", agent, p);
      } else if (priv_timer_expired(&p->next_tick, now)) {
        switch (stun_timer_refresh(&p->timer)) {
          case STUN_USAGE_TIMER_RETURN_TIMEOUT:
            {
              // case: error, abort processing //
              ICE_DEBUG("Agent %p : Retransmissions failed, giving up on connectivity check %p", agent, p);
              candidate_check_pair_fail(stream, agent, p);

              break;
            }
          case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
            {
              /* case: not ready, so schedule a new timeout */
              unsigned int timeout = stun_timer_remainder (&p->timer);
              ICE_DEBUG("Agent %p :STUN transaction retransmitted (timeout %dms).",
                     agent, timeout);

              agent_socket_send(p->sockptr, &p->remote->addr,
                  (char *)p->stun_buffer,
                  stun_message_length_new (&p->stun_message));


              /* note: convert from milli to microseconds for g_time_val_add() */
              p->next_tick = *now;

              //g_time_val_add (&p->next_tick, timeout * 1000);
              ICE_DEBUG("add timeval");
              print_timeval(&p->next_tick);
              add_microseconds_to_timeval(&p->next_tick, timeout * 1000);
              print_timeval(&p->next_tick);

              keep_timer_going = ICE_TRUE;
              break;
            }
          case STUN_USAGE_TIMER_RETURN_SUCCESS:
            {
              unsigned int timeout = stun_timer_remainder (&p->timer);

              /* note: convert from milli to microseconds for g_time_val_add() */
              p->next_tick = *now;
              
              //g_time_val_add (&p->next_tick, timeout * 1000);
              ICE_DEBUG("add timeval");
              print_timeval(&p->next_tick);
              add_microseconds_to_timeval(&p->next_tick, timeout * 1000);
              print_timeval(&p->next_tick);

              keep_timer_going = ICE_TRUE;
              break;
            }
          default:
            /* Nothing to do. */
            break;
        }
      }
    }

    if (p->state == ICE_CHECK_FROZEN)
      ++frozen;
    else if (p->state == ICE_CHECK_IN_PROGRESS)
      ++s_inprogress;
    else if (p->state == ICE_CHECK_WAITING)
      ++waiting;
    else if (p->state == ICE_CHECK_SUCCEEDED)
      ++s_succeeded;
    else if (p->state == ICE_CHECK_DISCOVERED)
      ++s_discovered;

    if ((p->state == ICE_CHECK_SUCCEEDED || p->state == ICE_CHECK_DISCOVERED)
        && p->nominated)
      ++s_nominated;
    else if ((p->state == ICE_CHECK_SUCCEEDED ||
            p->state == ICE_CHECK_DISCOVERED) && !p->nominated)
      ++s_waiting_for_nomination;

  } //connchecks list

  ICE_DEBUG("pair info, frozen=%u,inprogress=%u,waiting=%u,secceeded=%u,"
        "discovered=%u,nominated=%u,wait_for_nomination=%u",
        frozen,s_inprogress,waiting,s_succeeded,s_discovered,
        s_nominated,s_waiting_for_nomination);

  /* note: keep the timer going as long as there is work to be done */
  if (s_inprogress)
    keep_timer_going = ICE_TRUE;
  
  /* note: if some components have established connectivity,
   *       but yet no nominated pair, keep timer going */
  if (s_nominated < stream->n_components && s_waiting_for_nomination) {
    keep_timer_going = ICE_TRUE;
    if (agent->controlling_mode) {
      component_t *component = NULL;

      TAILQ_FOREACH(component,&stream->components,list) {
        candidate_check_pair_t *p = NULL;
        TAILQ_FOREACH(p,&stream->connchecks,list) {
     	     /* note: highest priority item selected (list always sorted) */
	        if (p->component_id == component->id &&
              (p->state == ICE_CHECK_SUCCEEDED ||
               p->state == ICE_CHECK_DISCOVERED)) {
	           ICE_DEBUG("Agent %p : restarting check %p as the nominated pair.", agent, p);
	           p->nominated = ICE_TRUE;
	           priv_conn_check_initiate (agent, p);
	           break; /* move to the next component */
	         }
	     }
      }
    }
  }

  {
    static int tick_counter = 0;
    if (tick_counter++ % 50 == 0 || keep_timer_going != ICE_TRUE)
      ICE_DEBUG("Agent %p : timer tick #%u: %u frozen, %u in-progress, "
          "%u waiting, %u succeeded, %u discovered, %u nominated, "
          "%u waiting-for-nom.", agent,
          tick_counter, frozen, s_inprogress, waiting, s_succeeded,
          s_discovered, s_nominated, s_waiting_for_nomination);
  }

  return keep_timer_going;
}

/*
 * Updates the check list state.
 *
 * Implements parts of the algorithm described in 
 * ICE sect 8.1.2. "Updating States" (ID-19): if for any 
 * component, all checks have been completed and have
 * failed, mark that component's state to NICE_CHECK_FAILED.
 *
 * Sends a component state changesignal via 'agent'.
 */
static void
priv_update_check_list_failed_components(agent_t *agent, stream_t *stream)
{
   candidate_discovery_t *d = NULL;
   uint32_t c, components = stream->n_components;

   ICE_DEBUG("priv_update_check_list_failed_components");

   /* note: emitting a signal might cause the client 
    *       to remove the stream, thus the component count
    *       must be fetched before entering the loop */
   if ( agent == NULL || stream == NULL ) 
      return;
   components = stream->n_components;
   TAILQ_FOREACH(d,&agent->discovery_list,list) {
      /* There is still discovery ogoing for this stream,
       * so don't fail any of it's candidates. */
      if (d->stream == stream && !d->done)
         return;
   }

   if (!TAILQ_EMPTY(&agent->discovery_list)) {
      ICE_DEBUG("discovery list not empty");
      return;
   }

   // note: iterate the conncheck list for each component separately //
   for (c = 0; c < components; c++) {
      component_t *comp = NULL;
      candidate_check_pair_t *p = NULL;

      if (agent_find_component(agent, stream->id, c+1, NULL, &comp) != ICE_OK)
         continue;

      TAILQ_FOREACH(p,&stream->connchecks,list) {
         if ( (p->agent != agent) || (p->stream_id != stream->id) ) {
            ICE_ERROR("stream info mismatched");
            return;
         }

         if (p->component_id == (c + 1)) {
            if (p->state != ICE_CHECK_FAILED)
               break;
         }
      }
 
      /* note: all checks have failed
       * Set the component to FAILED only if it actually had remote candidates
       * that failed.. */
      if (comp != NULL && !list_empty(&comp->remote_candidates.list)) {
        ICE_DEBUG("component failed, sid=%u, cid=%u", stream->id, c + 1);
        agent_signal_component_state_change (agent, 
  				   stream->id,
				   (c + 1), /* component-id */
				   ICE_COMPONENT_STATE_FAILED);
      }
   }

   return;
}


/*
 * Timer callback that handles initiating and managing connectivity
 * checks (paced by the Ta timer).
 *
 * This function is designed for the g_timeout_add() interface.
 *
 * @return will return FALSE when no more pending timers.
 */
static int 
priv_conn_check_tick_unlocked(agent_t *agent)
{
  candidate_check_pair_t *pair = NULL;
  int keep_timer_going = ICE_FALSE;
  struct timeval now;
  stream_t *stream = NULL;

  /* step: process ongoing STUN transactions */
  gettimeofday(&now,NULL);

  /* step: find the highest priority waiting check and send it */
  TAILQ_FOREACH(stream,&agent->streams,list) {

    pair = priv_conn_check_find_next_waiting(&stream->connchecks);
    if (pair)
      break;
  }

  if (pair) {
    priv_conn_check_initiate(agent, pair);
    keep_timer_going = ICE_TRUE;
  } else {
    keep_timer_going = priv_conn_check_unfreeze_next(agent);
  }

  TAILQ_FOREACH(stream,&agent->streams,list) {
    int res = priv_conn_check_tick_stream(stream, agent, &now);
    if (res == ICE_TRUE)
      keep_timer_going = ICE_TRUE;
  }

  //ICE_DEBUG("keep timer going, value=%u",keep_timer_going);
  /* step: stop timer if no work left */
  if (keep_timer_going != ICE_TRUE) {
    ICE_DEBUG("Agent %p: stopping conncheck timer", agent);
    TAILQ_FOREACH(stream,&agent->streams,list) {
      component_t *component = NULL;
      priv_update_check_list_failed_components(agent, stream);
      TAILQ_FOREACH(component,&stream->components,list) {
        priv_update_check_list_state_for_ready(agent, stream, component);
      }
    }

    /* Stopping the timer so destroy the source.. this will allow
       the timer to be reset if we get a set_remote_candidates after this
       point */
    if ( agent->conncheck_timer_ev != NULL ) {
       //event_del(agent->conncheck_timer_ev);
       destroy_event_info(agent->base, agent->conncheck_timer_ev);
       agent->conncheck_timer_ev = NULL;
    }

    /* XXX: what to signal, is all processing now really done? */
    ICE_DEBUG("Agent %p : changing conncheck state to COMPLETED.", agent);
  }

  return keep_timer_going;
}

void 
priv_conn_check_tick(int fd, short event, void *arg) {

  int ret; 
  agent_t *agent = (agent_t*)arg;

  ret = priv_conn_check_tick_unlocked(agent);
  if ( ret == ICE_FALSE ) {
     ICE_DEBUG("no more conncheck timer");
  }
  return;
}

void 
priv_conn_keepalive_tick(int fd, short event, void *arg) {

  agent_t *agent = (agent_t*)arg;
  int ret;

  if ( agent->keepalive_timer_ev == NULL ) {
     ICE_ERROR("timer was destroyed");
     return;
  }

  ret = priv_conn_keepalive_tick_unlocked(agent);
  if (ret == ICE_FALSE) {
    if (agent->keepalive_timer_ev != NULL) {
      //event_del(agent->keepalive_timer_ev);
      destroy_event_info(agent->base, agent->keepalive_timer_ev);
      agent->keepalive_timer_ev = NULL;
    }
  }
  return;
}

/*
 * Initiates the next pending connectivity check.
 * 
 * @return TRUE if a pending check was scheduled
 */
int 
conn_check_schedule_next(agent_t *agent)
{
  int ret = priv_conn_check_unfreeze_next(agent);

  ICE_DEBUG("Agent %p : priv_conn_check_unfreeze_next returned %d", agent, ret);

  if (agent->discovery_unsched_items > 0) {
    ICE_DEBUG("Agent %p : WARN: starting conn checks before local candidate gathering is finished.", agent);
  }

  /* step: call once imediately */
  ret = priv_conn_check_tick_unlocked(agent);
  ICE_DEBUG("Agent %p : priv_conn_check_tick_unlocked returned %d", agent, ret);

  /* step: schedule timer if not running yet */
  if (ret == ICE_TRUE && agent->conncheck_timer_ev == NULL) {
     agent->conncheck_timer_ev = create_event_info(agent->base,EV_PERSIST,
         priv_conn_check_tick,agent->timer_ta * 1000);
  }

  /* step: also start the keepalive timer */
  if (agent->keepalive_timer_ev == NULL) {
     agent->keepalive_timer_ev = create_event_info(agent->base,EV_PERSIST,
         priv_conn_keepalive_tick,ICE_AGENT_TIMER_TR_DEFAULT);
  }

  ICE_DEBUG("Agent %p : conn_check_schedule_next returning %d", agent, ret);
  return ret;
}

int 
conncheck_stun_validater(StunAgent *agent,
    StunMessage *message, uint8_t *username, uint16_t username_len,
        uint8_t **password, size_t *password_len, void *user_data)
{
   conncheck_validater_data *data;
   candidate_t *candlist;
   struct list_head *i;
   char *ufrag = NULL;
   size_t ufrag_len;
   int msn_msoc_nice_compatibility;

   data = (conncheck_validater_data*) user_data;
   msn_msoc_nice_compatibility =
      data->agent->compatibility == ICE_COMPATIBILITY_MSN ||
      data->agent->compatibility == ICE_COMPATIBILITY_OC2007;

   if (data->agent->compatibility == ICE_COMPATIBILITY_OC2007 &&
       stun_message_get_class (message) == STUN_RESPONSE)
      candlist = &data->component->remote_candidates;
   else 
      candlist = &data->component->local_candidates;

   list_for_each(i,&candlist->list) {
      candidate_t *cand = list_entry(i,candidate_t,list);

      ufrag = NULL;
      if (cand->username)
         ufrag = cand->username;
      else if (data->stream)
         ufrag = data->stream->local_ufrag;
      ufrag_len = ufrag? strlen (ufrag) : 0;

      if (ufrag && msn_msoc_nice_compatibility)
         ufrag = (char *)base64_decode ((const unsigned char*)ufrag, ufrag_len, &ufrag_len);

      if (ufrag == NULL)
         continue;

      ICE_DEBUG("Comparing username/ufrag of len %d and %zu, equal=%d",
          username_len, ufrag_len, username_len >= ufrag_len ?
          memcmp (username, ufrag, ufrag_len) : 0);

      if (ufrag_len > 0 && username_len >= ufrag_len &&
          memcmp(username, ufrag, ufrag_len) == 0) {
         char *pass = NULL;

         if (cand->password)
            pass = cand->password;
         else if(data->stream->local_password[0])
            pass = data->stream->local_password;

         if (pass) {
            *password = (uint8_t *) pass;
            *password_len = strlen (pass);

            if (msn_msoc_nice_compatibility) {
               size_t pass_len;

               data->password = base64_decode((const unsigned char*)pass, *password_len, &pass_len);
               *password = data->password;
               *password_len = pass_len;
            }
         }
         if (msn_msoc_nice_compatibility)
            free (ufrag);

         ICE_DEBUG("Found valid username, username=%s, password=%s", username, *password);
         return ICE_TRUE;
      }

      if (msn_msoc_nice_compatibility)
         free (ufrag);      
   } 

   ICE_DEBUG("failed to validate conncheck");
   return ICE_FALSE;
}

/*
 * Recalculates priorities of all candidate pairs. This
 * is required after a conflict in ICE roles.
 */
static void priv_recalculate_pair_priorities(agent_t *agent)
{
  candidate_check_pair_t *p = NULL;
  stream_t *stream = NULL;

  TAILQ_FOREACH(stream,&agent->streams,list) {
    TAILQ_FOREACH(p,&stream->connchecks,list) {
      p->priority = agent_candidate_pair_priority(agent, p->local, p->remote);
    }
  }
}

/*
 * Change the agent role if different from 'control'. Can be
 * initiated both by handling of incoming connectivity checks,
 * and by processing the responses to checks sent by us.
 */
static void 
priv_check_for_role_conflict (agent_t *agent, int control)
{
  /* role conflict, change mode; wait for a new conn. check */
  if (control != agent->controlling_mode) {
    ICE_DEBUG("Agent %p : Role conflict, changing agent role to %d.", agent, control);
    agent->controlling_mode = control;
    /* the pair priorities depend on the roles, so recalculation
     * is needed */
    priv_recalculate_pair_priorities (agent);
  }
  else {
    ICE_DEBUG("Agent %p : Role conflict, agent role already changed to %d.", agent, control);
  }

}

static void 
priv_reply_to_conn_check(agent_t *agent, stream_t *stream, component_t *component, candidate_t *rcand, 
    const address_t *toaddr, socket_t *sockptr, size_t  rbuf_len, uint8_t *rbuf, int use_candidate)
{
  ICE_DEBUG("reply to conncheck");
  ICE_HEXDUMP(rbuf,(int)rbuf_len,"rsp");

  //g_assert (rcand == NULL || nice_address_equal(&rcand->addr, toaddr) == ICE_TRUE);
  if (rcand != NULL && address_equal(&rcand->addr, toaddr) != ICE_TRUE) {
     ICE_ERROR("not reply to conncheck");
     return;
  }

  {
    char tmpbuf[INET6_ADDRSTRLEN];
    char tmpbuf1[INET6_ADDRSTRLEN];
    address_to_string (toaddr, tmpbuf);
    address_to_string (&sockptr->addr, tmpbuf1);
    ICE_DEBUG("Agent %p : STUN-CC RESP from '%s:%u' to '%s:%u', socket=%u, len=%u, cand=%p (c-id:%u), use-cand=%d.", agent,
        tmpbuf1, address_get_port (&sockptr->addr),
        tmpbuf, address_get_port (toaddr),
             sockptr->fd ? sockptr->fd : -1,
        (unsigned)rbuf_len,
        rcand, component->id,
        (int)use_candidate);
  }

  agent_socket_send(sockptr, toaddr, (const char*)rbuf, rbuf_len);

  if (rcand) {
    /* note: upon successful check, make the reserve check immediately */
    priv_schedule_triggered_check(agent, stream, component, sockptr, rcand, use_candidate);
    ICE_DEBUG("use_candidate=%u",use_candidate);
    if (use_candidate)
      priv_mark_pair_nominated(agent, stream, component, rcand);
  }

  return;
}


void* 
memdup(const void* d, size_t s) { 
   void* p; 
   return ((p = malloc(s))?memcpy(p, d, s):NULL);
}
/*
 * Stores information of an incoming STUN connectivity check
 * for later use. This is only needed when a check is received
 * before we get information about the remote candidates (via
 * SDP or other signaling means).
 *
 * @return non-zero on error, zero on success
 */
static int 
priv_store_pending_check (agent_t *agent, component_t *component,
    const address_t *from, socket_t *sockptr, uint8_t *username,
    uint16_t username_len, uint32_t priority, int use_candidate)
{
  incoming_check_t *icheck;
  int num;
  ICE_DEBUG("Agent %p : Storing pending check.", agent);
 
  num = 0; 
  TAILQ_FOREACH(icheck,&component->incoming_checks,list) {
     num++;
  }
  if ( !TAILQ_EMPTY(&component->incoming_checks) &&
      num >= ICE_AGENT_MAX_REMOTE_CANDIDATES) {
    ICE_DEBUG("Agent %p : WARN: unable to store information for early incoming check.", agent);
    return -1;
  }

  icheck = ICE_MALLOC(incoming_check_t);
  TAILQ_INSERT_HEAD(&component->incoming_checks,icheck,list);
  icheck->from = *from;
  icheck->local_socket = sockptr;
  icheck->priority = priority;
  icheck->use_candidate = use_candidate;
  icheck->username_len = username_len;
  icheck->username = NULL;
  if (username_len > 0)
    icheck->username = (uint8_t*)memdup(username, username_len);

  return 0;
}

/*
 * Unfreezes the next next connectivity check in the list after
 * check 'success_check' has successfully completed.
 *
 * See sect 7.1.2.2.3 (Updating Pair States) of ICE spec (ID-19).
 * 
 * @param agent context
 * @param ok_check a connectivity check that has just completed
 *
 * @return TRUE on success, and FALSE if no frozen candidates were found.
 */
static void priv_conn_check_unfreeze_related (agent_t *agent, stream_t *stream, candidate_check_pair_t *ok_check)
{
  candidate_check_pair_t *p = NULL;
  int unfrozen = 0;

  if ( ok_check == NULL || ok_check->state == ICE_CHECK_SUCCEEDED 
      || stream == NULL || stream->id != ok_check->stream_id )
     return;

  /* step: perform the step (1) of 'Updating Pair States' */
  TAILQ_FOREACH(p,&stream->connchecks,list) {
    if (p->stream_id == ok_check->stream_id) {
      if (p->state == ICE_CHECK_FROZEN &&
	       strcmp(p->foundation, ok_check->foundation) == 0) {
	     ICE_DEBUG("Agent %p : Unfreezing check %p (after successful check %p).", agent, p, ok_check);
	     p->state = ICE_CHECK_WAITING;
        ICE_DEBUG("Agent %p : pair %p state WAITING", agent, p);
	     ++unfrozen;
      }
    }
  }

  /* step: perform the step (2) of 'Updating Pair States' */
  stream = agent_find_stream(agent, ok_check->stream_id);
  if (stream_all_components_ready(stream) == ICE_OK) {
    /* step: unfreeze checks from other streams */
    stream_t *s = NULL;
    TAILQ_FOREACH(s,&agent->streams,list) {
	    candidate_check_pair_t *p = NULL;
      TAILQ_FOREACH(p,&stream->connchecks,list) {
	      if (p->stream_id == s->id &&
      	    p->stream_id != ok_check->stream_id) {
	        if (p->state == ICE_CHECK_FROZEN &&
      	      strcmp (p->foundation, ok_check->foundation) == 0) {
	          ICE_DEBUG("Agent %p : Unfreezing check %p from stream %u (after successful check %p).", agent, p, s->id, ok_check);
      	    p->state = ICE_CHECK_WAITING;
             ICE_DEBUG("Agent %p : pair %p state WAITING", agent, p);
      	    ++unfrozen;
	        }
	      }
      }
      /* note: only unfreeze check from one stream at a time */
      if (unfrozen)
	      break;
    }
  }    
  
  ICE_DEBUG("check unfreezing, unfrozen=%u",unfrozen);
  if (unfrozen == 0) 
    priv_conn_check_unfreeze_next(agent);
}

/*
 * Adds a new pair, discovered from an incoming STUN response, to 
 * the connectivity check list.
 *
 * @return created pair, or NULL on fatal (memory allocation) errors
 */
static candidate_check_pair_t*
priv_add_peer_reflexive_pair(agent_t *agent, uint32_t stream_id, uint32_t component_id, 
   candidate_t *local_cand, candidate_check_pair_t *parent_pair)
{
  candidate_check_pair_t *pair;
  stream_t *stream;

  pair = ICE_MALLOC(candidate_check_pair_t);
  if ( pair == NULL )
     return NULL;
  ICE_MEMZERO(pair,candidate_check_pair_t);

  stream = agent_find_stream(agent, stream_id);
  if ( stream == NULL )
     return NULL;
  
  //FIXME: check whether pair already exists?
  pair->agent = agent;
  pair->stream_id = stream_id;
  pair->component_id = component_id;;
  pair->local = local_cand;
  pair->remote = parent_pair->remote;
  pair->sockptr = (socket_t*)local_cand->sockptr;
  pair->state = ICE_CHECK_DISCOVERED;
  ICE_ERROR("new reflexive peer pair, pair=%p, foundation=%s(%p)", 
            pair, pair->remote->foundation, pair->remote);
  print_candidate(local_cand,"local");
  print_candidate(parent_pair->remote,"remote");
  snprintf (pair->foundation, ICE_CANDIDATE_PAIR_MAX_FOUNDATION, "%s:%s",
      local_cand->foundation, parent_pair->remote->foundation);
  //if (agent->controlling_mode == ICE_TRUE)
  if (agent->controlling_mode)
    pair->priority = candidate_pair_priority(pair->local->priority,
        pair->remote->priority);
  else
    pair->priority = candidate_pair_priority(pair->remote->priority,
        pair->local->priority);
  pair->nominated = ICE_FALSE;
  pair->controlling = agent->controlling_mode;
  ICE_ERROR("added a new peer-discovered pair, f=%s, prio=%lu", pair->foundation, pair->priority);
  
  //FIXME: inherited nominated flag from parent?
  pair->nominated = parent_pair->nominated;
  ICE_ERROR("nominated flag inherited, nominated=%u, pair=%p, parent_pair=%p", 
            pair->nominated, pair, parent_pair);

  conn_check_insert(&stream->connchecks,pair);

  return pair;
}


/*
 * Checks whether the mapped address in connectivity check response 
 * matches any of the known local candidates. If not, apply the
 * mechanism for "Discovering Peer Reflexive Candidates" ICE ID-19)
 *
 * @param agent context pointer
 * @param stream which stream (of the agent)
 * @param component which component (of the stream)
 * @param p the connectivity check pair for which we got a response
 * @param socketptr socket used to send the reply
 * @param mapped_sockaddr mapped address in the response
 *
 * @return pointer to a new pair if one was created, otherwise NULL
 */
// Renamed to priv_process_response_check_for_reflexive
static candidate_check_pair_t*
priv_process_response_check_for_peer_reflexive(agent_t *agent, stream_t *stream, 
    component_t *component, candidate_check_pair_t *p, socket_t *sockptr, 
    struct sockaddr *mapped_sockaddr, candidate_t *local_candidate, candidate_t *remote_candidate)
{
  candidate_check_pair_t *new_pair = NULL;
  address_t mapped;
  struct list_head *j;
  int local_cand_matches = ICE_FALSE;

  address_set_from_sockaddr(&mapped, mapped_sockaddr);

  list_for_each(j,&component->local_candidates.list) {
    candidate_t *cand = list_entry(j,candidate_t,list);
    if (address_equal (&mapped, &cand->addr)) {
      candidate_check_pair_t *pair = NULL;
      local_cand_matches = ICE_TRUE;

      /* We always need to select the peer-reflexive Candidate Pair in the case
       * of a TCP-ACTIVE local candidate, so we find it even if an incoming
       * check matched an existing pair because it could be the original
       * ACTIVE-PASSIVE candidate pair which was retriggered */
      TAILQ_FOREACH(pair,&stream->connchecks,list) {
        if (pair->local == cand && remote_candidate == pair->remote) {
          new_pair = pair;
          ICE_DEBUG("Agent %p : got pair matched, pair=%p", agent, new_pair);
          break;
        }
      }
      break;
    }
  }

  if (local_cand_matches == ICE_TRUE) {
    /* note: this is same as "adding to VALID LIST" in the spec
       text */
    p->state = ICE_CHECK_SUCCEEDED;
    ICE_DEBUG("Agent %p : conncheck %p SUCCEEDED, pair=%p", agent, p, new_pair);
    priv_conn_check_unfreeze_related(agent, stream, p);
  }
  else {
    ICE_DEBUG("no local candidate found");
    candidate_t *cand =
      discovery_add_peer_reflexive_candidate(agent,
					      stream->id,
					      component->id,
					      &mapped,
					      sockptr,
					      local_candidate,
					      remote_candidate);
    p->state = ICE_CHECK_FAILED;
    ICE_DEBUG("Agent %p : pair %p state FAILED", agent, p);

    /* step: add a new discovered pair (see RFC 5245 7.1.3.2.2
	       "Constructing a Valid Pair") */
    ICE_DEBUG("Agent %p : adding new pair, cand=%p", agent, cand);
    new_pair = priv_add_peer_reflexive_pair (agent, stream->id, component->id, cand, p);
    ICE_ERROR("Agent %p : conncheck %p FAILED, %p DISCOVERED.", agent, p, new_pair);
  }

  ICE_DEBUG("Agent %p : got pair matched, pair=%p", agent, new_pair);
  return new_pair;
}


/*
 * Tries to match STUN reply in 'buf' to an existing STUN connectivity
 * check transaction. If found, the reply is processed. Implements
 * section 7.1.2 "Processing the Response" of ICE spec (ID-19).
 *
 * @return TRUE if a matching transaction is found
 */
static int 
priv_map_reply_to_conn_check_request(agent_t *agent, stream_t *stream, component_t *component, socket_t *sockptr, 
        const address_t *from, candidate_t *local_candidate, candidate_t *remote_candidate, StunMessage *resp)
{
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } sockaddr;
  socklen_t socklen = sizeof (sockaddr);
  StunUsageIceReturn res;
  int trans_found = ICE_FALSE;
  StunTransactionId discovery_id;
  StunTransactionId response_id;
  candidate_check_pair_t *p = NULL;

  stun_message_id(resp, response_id);

  TAILQ_FOREACH(p,&stream->connchecks,list) {

    ICE_DEBUG("buffer, pair=%p, buffer=%p", p, p->stun_message.buffer);
    if (p->stun_message.buffer) {
      stun_message_id(&p->stun_message, discovery_id);

      if (memcmp(discovery_id, response_id, sizeof(StunTransactionId)) == 0) {
        res = stun_usage_ice_conncheck_process(resp, &sockaddr.storage, &socklen,
                      agent_to_ice_compatibility (agent));
        ICE_DEBUG("Agent %p : stun_bind_process/conncheck for %p res %d "
            "(controlling=%d).", agent, p, (int)res, agent->controlling_mode);

        if (res == STUN_USAGE_ICE_RETURN_SUCCESS ||
            res == STUN_USAGE_ICE_RETURN_NO_MAPPED_ADDRESS) {
          /* case: found a matching connectivity check request */

          candidate_check_pair_t *ok_pair = NULL;

          ICE_DEBUG("Agent %p : conncheck %p MATCHED, res=%u", agent, p, res);
          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;

          /* step: verify that response came from the same IP address we
           *       sent the original request to (see 7.1.2.1. "Failure
           *       Cases") */
          if (address_equal (from, &p->remote->addr) != ICE_TRUE) {

            p->state = ICE_CHECK_FAILED;
            {
              char tmpbuf[INET6_ADDRSTRLEN];
              char tmpbuf2[INET6_ADDRSTRLEN];
              ICE_DEBUG("Agent %p : conncheck %p FAILED"
                  " (mismatch of source address).", agent, p);
              address_to_string (&p->remote->addr, tmpbuf);
              address_to_string (from, tmpbuf2);
              ICE_DEBUG("Agent %p : '%s:%u' != '%s:%u'", agent,
                  tmpbuf, address_get_port (&p->remote->addr),
                  tmpbuf2, address_get_port (from));
            }
            trans_found = ICE_TRUE;
            break;
          }

          /* note: CONNECTED but not yet READY, see docs */

          /* step: handle the possible case of a peer-reflexive
           *       candidate where the mapped-address in response does
           *       not match any local candidate, see 7.1.2.2.1
           *       "Discovering Peer Reflexive Candidates" ICE ID-19) */

          if (res == STUN_USAGE_ICE_RETURN_NO_MAPPED_ADDRESS) {
            /* note: this is same as "adding to VALID LIST" in the spec
               text */
            p->state = ICE_CHECK_SUCCEEDED;
            ICE_DEBUG("Agent %p : Mapped address not found."
                " conncheck %p SUCCEEDED, nominated=%u.", agent, p, p->nominated);
            priv_conn_check_unfreeze_related(agent, stream, p);
          } else {
            ICE_DEBUG("mapped address found, pair=%p",p);
            ok_pair = priv_process_response_check_for_peer_reflexive (agent,
                stream, component, p, sockptr, &sockaddr.addr,
                local_candidate, remote_candidate);
            ICE_DEBUG("Agent %p : got pair matched, pair=%p", agent, ok_pair);
          }


          if (!ok_pair)
            ok_pair = p;

          /* step: updating nominated flag (ICE 7.1.2.2.4 "Updating the
             Nominated Flag" (ID-19) */
          if (ok_pair->nominated == ICE_TRUE) {
            priv_update_selected_pair(agent, component, ok_pair);

            /* Do not step down to CONNECTED if we're already at state READY*/
            ICE_DEBUG("component info, state=%u(%u)",component->state, ICE_COMPONENT_STATE_READY);
            if (component->state != ICE_COMPONENT_STATE_READY) {
              /* step: notify the client of a new component state (must be done
               *       before the possible check list state update step */
              agent_signal_component_state_change(agent,
                  stream->id, component->id, ICE_COMPONENT_STATE_CONNECTED);
            }
          }

          /* step: update pair states (ICE 7.1.2.2.3 "Updating pair
             states" and 8.1.2 "Updating States", ID-19) */
          priv_update_check_list_state_for_ready(agent, stream, component);

          trans_found = ICE_TRUE;
        } else if (res == STUN_USAGE_ICE_RETURN_ROLE_CONFLICT) {
          /* case: role conflict error, need to restart with new role */
          ICE_DEBUG("Agent %p : conncheck %p ROLE CONFLICT, restarting", agent, p);
          /* note: our role might already have changed due to an
           * incoming request, but if not, change role now;
           * follows ICE 7.1.2.1 "Failure Cases" (ID-19) */
          priv_check_for_role_conflict(agent, !p->controlling);

          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          p->state = ICE_CHECK_WAITING;
          ICE_DEBUG("Agent %p : pair %p state WAITING", agent, p);
          trans_found = ICE_TRUE;
        } else {
          /* case: STUN error, the check STUN context was freed */
          ICE_DEBUG("Agent %p : conncheck %p FAILED.", agent, p);
          p->stun_message.buffer = NULL;
          p->stun_message.buffer_len = 0;
          trans_found = ICE_TRUE;
        }
      }
    }
  }

  //stream->conncheck_list = prune_cancelled_conn_check(stream->conncheck_list);
  prune_cancelled_conn_check(&stream->connchecks);

  return trans_found;
}

/*
 * Tries to match STUN reply in 'buf' to an existing STUN discovery
 * transaction. If found, a reply is sent.
 *
 * @return TRUE if a matching transaction is found
 */
static int 
priv_map_reply_to_discovery_request(agent_t *agent, StunMessage *resp)
{
  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } sockaddr;
  socklen_t socklen = sizeof (sockaddr);

  union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
  } alternate;
  socklen_t alternatelen = sizeof (sockaddr);

  candidate_discovery_t *d = NULL;
  StunUsageBindReturn res;
  int trans_found = ICE_FALSE;
  StunTransactionId discovery_id;
  StunTransactionId response_id;
  stun_message_id (resp, response_id);

  TAILQ_FOREACH(d,&agent->discovery_list,list ) {
    if (d->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE &&
        d->stun_message.buffer) {
      stun_message_id (&d->stun_message, discovery_id);

      if (memcmp (discovery_id, response_id, sizeof(StunTransactionId)) == 0) {
        res = stun_usage_bind_process (resp, &sockaddr.addr,
            &socklen, &alternate.addr, &alternatelen);
        ICE_DEBUG("Agent %p : stun_bind_process/disc for %p res %d.",
            agent, d, (int)res);

        if (res == STUN_USAGE_BIND_RETURN_ALTERNATE_SERVER) {
          /* handle alternate server */
          address_t niceaddr;
          address_set_from_sockaddr (&niceaddr, &alternate.addr);
          d->server = niceaddr;

          d->pending = ICE_FALSE;
        } else if (res == STUN_USAGE_BIND_RETURN_SUCCESS) {
          /* case: successful binding discovery, create a new local candidate */
          address_t niceaddr;
          address_set_from_sockaddr (&niceaddr, &sockaddr.addr);

          discovery_add_server_reflexive_candidate(
              d->agent,
              d->stream->id,
              d->component->id,
              &niceaddr,
              ICE_CANDIDATE_TRANSPORT_UDP,
              d->nicesock,
              ICE_FALSE);
          if (d->agent->use_ice_tcp)
            discovery_discover_tcp_server_reflexive_candidates (
                d->agent,
                d->stream->id,
                d->component->id,
                &niceaddr,
                d->nicesock);

          d->stun_message.buffer = NULL;
          d->stun_message.buffer_len = 0;
          d->done = ICE_TRUE;
          trans_found = ICE_TRUE;
        } else if (res == STUN_USAGE_BIND_RETURN_ERROR) {
          /* case: STUN error, the check STUN context was freed */
          d->stun_message.buffer = NULL;
          d->stun_message.buffer_len = 0;
          d->done = TRUE;
          trans_found = ICE_TRUE;
        }
      }
    }
    if ( trans_found == ICE_TRUE )
       break;
  }

  return trans_found;
}

static int 
priv_map_reply_to_keepalive_conncheck (agent_t *agent,
    component_t *component, StunMessage *resp)
{
  StunTransactionId conncheck_id;
  StunTransactionId response_id;
  stun_message_id (resp, response_id);

  ICE_DEBUG("component info, state=%u(%u), sid=%u, cid=%u, agent=%p", 
            component->state, ICE_COMPONENT_STATE_DISCONNECTED, 
            component->stream->id, component->id, agent);
  if (component->selected_pair.keepalive.stun_message.buffer) {
      stun_message_id (&component->selected_pair.keepalive.stun_message,
          conncheck_id);
      if (memcmp (conncheck_id, response_id, sizeof(StunTransactionId)) == 0) {
        ICE_DEBUG("FIXME: Keepalive for selected pair received, agent=%p", agent);
        /*if (component->selected_pair.keepalive.tick_source) {
          g_source_destroy (component->selected_pair.keepalive.tick_source);
          g_source_unref (component->selected_pair.keepalive.tick_source);
          component->selected_pair.keepalive.tick_source = NULL;
        }*/
        component->selected_pair.keepalive.stun_message.buffer = NULL;
        return ICE_TRUE;
      }
  }

  return FALSE;
}



int 
conn_check_handle_inbound_stun(agent_t *agent, stream_t *stream,
    component_t *component, socket_t *nicesock, const address_t *from,
    char *buf, int len) 
{
   union {
    struct sockaddr_storage storage;
    struct sockaddr addr;
   } sockaddr;
   static uint8_t rbuf[MAX_STUN_DATAGRAM_PAYLOAD];//1300 bytes
   size_t rbuf_len = MAX_STUN_DATAGRAM_PAYLOAD;
   conncheck_validater_data validater_data = {agent, stream, component, NULL};
   StunValidationStatus valid;
   struct list_head *i, *j;
   StunMessage req;
   StunMessage msg;
   int discovery_msg = ICE_FALSE;
   int control = agent->controlling_mode;
   uint8_t uname[ICE_STREAM_MAX_UNAME];
   uint32_t uname_len;
   uint8_t *username;
   uint16_t username_len;
   candidate_t *remote_candidate = NULL;
   candidate_t *remote_candidate2 = NULL;
   candidate_t *local_candidate = NULL;
   ssize_t res;

   address_copy_to_sockaddr(from, &sockaddr.addr);

   {// print info
      char tmpbuf[INET6_ADDRSTRLEN];
      char tmpbuf1[INET6_ADDRSTRLEN];
      address_to_string (from, tmpbuf);
      address_to_string (&nicesock->addr, tmpbuf1);
      ICE_DEBUG("Agent %p: inbound STUN packet for %u/%u (stream/component) from [%s]:%u to [%s]:%u (%u octets):",
          agent, stream->id, component->id, tmpbuf, address_get_port(from), 
          tmpbuf1, address_get_port(&nicesock->addr), len);
   }

   /* note: ICE  7.2. "STUN Server Procedures" (ID-19) */
   ICE_HEXDUMP(buf,len,"msg");
   valid = stun_agent_validate(&component->stun_agent, &req,
             (uint8_t *) buf, len, conncheck_stun_validater, &validater_data); 

   ICE_DEBUG("stun validation, valid=%u,success=%u",valid,STUN_VALIDATION_SUCCESS);

   /* Check for discovery candidates stun agents */
   if (valid == STUN_VALIDATION_BAD_REQUEST ||
       valid == STUN_VALIDATION_UNMATCHED_RESPONSE) {
      candidate_discovery_t *d = NULL;
      //list_for_each(i,&agent->discovery_list.list) {
      //   candidate_discovery_t *d = list_entry(i,candidate_discovery_t,list);
      TAILQ_FOREACH(d,&agent->discovery_list,list) {
         if (d->stream == stream && d->component == component &&
             d->nicesock == nicesock) {
            valid = stun_agent_validate (&d->stun_agent, &req,
                    (uint8_t *) buf, len, conncheck_stun_validater, &validater_data);

            if (valid == STUN_VALIDATION_UNMATCHED_RESPONSE)
              continue;

            discovery_msg = ICE_TRUE;
            break;
         }
      }
   }

   /* Check for relay refresh stun agents */
   if (valid == STUN_VALIDATION_BAD_REQUEST ||
       valid == STUN_VALIDATION_UNMATCHED_RESPONSE) {
      candidate_refresh_t *r = NULL;
      //list_for_each(i,&agent->refresh_list.list) {
      //   candidate_refresh_t *r = list_entry(i,candidate_refresh_t,list);
      TAILQ_FOREACH(r,&agent->refresh_list,list) {
         ICE_DEBUG("Comparing %p to %p, %p to %p and %p and %p to %p", r->stream, stream, 
               r->component, component, r->nicesock, r->candidate->sockptr, nicesock);
         if (r->stream == stream && r->component == component &&
             (r->nicesock == nicesock || r->candidate->sockptr == nicesock)) {
            valid = stun_agent_validate (&r->stun_agent, &req,
               (uint8_t *) buf, len, conncheck_stun_validater, &validater_data);
            ICE_DEBUG("Validating gave %d", valid);
            if (valid == STUN_VALIDATION_UNMATCHED_RESPONSE)
               continue;
            discovery_msg = ICE_TRUE;
            break;
         }
      }
   }

   if ( validater_data.password != NULL )
       free(validater_data.password);

   if (valid == STUN_VALIDATION_NOT_STUN ||
       valid == STUN_VALIDATION_INCOMPLETE_STUN ||
       valid == STUN_VALIDATION_BAD_REQUEST) {
      ICE_DEBUG("Incorrectly multiplexed STUN message ignored, agent=%p", agent);
      return ICE_FALSE;
   }

   if (valid == STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE) {
      ICE_DEBUG("Unknown mandatory attributes in message, agent=%p", agent);

      if (agent->compatibility != ICE_COMPATIBILITY_MSN &&
          agent->compatibility != ICE_COMPATIBILITY_OC2007) {
         rbuf_len = stun_agent_build_unknown_attributes_error (&component->stun_agent,
             &msg, rbuf, rbuf_len, &req);
         if (rbuf_len != 0)
           agent_socket_send(nicesock, from, (const char*)rbuf, rbuf_len);
      }
      return ICE_TRUE;
   }

   if (valid == STUN_VALIDATION_UNAUTHORIZED) {
      ICE_DEBUG("Integrity check failed, agent=%p", agent);

      if (stun_agent_init_error (&component->stun_agent, &msg, rbuf, rbuf_len,
            &req, STUN_ERROR_UNAUTHORIZED)) {
         rbuf_len = stun_agent_finish_message (&component->stun_agent, &msg, NULL, 0);
         if (rbuf_len > 0 && agent->compatibility != ICE_COMPATIBILITY_MSN &&
             agent->compatibility != ICE_COMPATIBILITY_OC2007)
            agent_socket_send (nicesock, from, (const char*)rbuf, rbuf_len);
      }
      return ICE_TRUE;
   }

   if (valid == STUN_VALIDATION_UNAUTHORIZED_BAD_REQUEST) {
      ICE_DEBUG("Integrity check failed - bad request, agent=%p", agent);
      if (stun_agent_init_error (&component->stun_agent, &msg, rbuf, rbuf_len,
            &req, STUN_ERROR_BAD_REQUEST)) {
         rbuf_len = stun_agent_finish_message (&component->stun_agent, &msg, NULL, 0);
         if (rbuf_len > 0 && agent->compatibility != ICE_COMPATIBILITY_MSN &&
             agent->compatibility != ICE_COMPATIBILITY_OC2007)
            agent_socket_send (nicesock, from, (const char*)rbuf, rbuf_len);
      }
      return ICE_TRUE;
   }

   username = (uint8_t *) stun_message_find (&req, STUN_ATTRIBUTE_USERNAME,
                   &username_len);


   list_for_each(i, &component->remote_candidates.list) {
      candidate_t *cand = list_entry(i,candidate_t,list);
      if (address_equal (from, &cand->addr)) {
         remote_candidate = cand;
         break;
      }
   }
   list_for_each(i, &component->local_candidates.list) {
      candidate_t *cand = list_entry(i,candidate_t,list);
      if (address_equal (&nicesock->addr, &cand->addr)) {
         local_candidate = cand;
         break;
      }
   }

   ICE_DEBUG("get local and remote candidates, local=%p, remote=%p, comp=%u",
         local_candidate,remote_candidate,agent->compatibility);
   print_address(from);

   if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE ||
       agent->compatibility == ICE_COMPATIBILITY_MSN ||
       agent->compatibility == ICE_COMPATIBILITY_OC2007) {

      list_for_each(i,&component->remote_candidates.list) {
         list_for_each(j,&component->local_candidates.list) {
            int inbound = 0;
            candidate_t *rcand = list_entry(i,candidate_t,list);
            candidate_t *lcand = list_entry(j,candidate_t,list);
            /* If we receive a response, then the username is local:remote */
            if (agent->compatibility != ICE_COMPATIBILITY_MSN) {
               if (stun_message_get_class (&req) == STUN_REQUEST ||
                   stun_message_get_class (&req) == STUN_INDICATION) {
                  inbound = 1;
               } else {
                  inbound = 0;
               }
            }

            uname_len = priv_create_username (agent, stream,
                component->id,  rcand, lcand,
                uname, sizeof (uname), inbound);

            /*ICE_DEBUG("Comparing usernames of size %d and %d: %d",
                username_len, uname_len, username && uname_len == username_len &&
                memcmp (username, uname, uname_len) == 0);
            ICE_HEXDUMP(username, (username ? username_len : 0),"first_username");
            ICE_HEXDUMP(uname, uname_len,"second_username");*/

            if (username &&
                uname_len == username_len &&
                memcmp (uname, username, username_len) == 0) { 
               local_candidate = lcand;
               remote_candidate2 = rcand;
               break;
            }    

         }
         if ( remote_candidate2 != NULL )
            break;
      }
   }

   if (list_empty(&component->remote_candidates.list) &&
       agent->compatibility == ICE_COMPATIBILITY_GOOGLE &&
       local_candidate == NULL &&
       discovery_msg == ICE_FALSE) {
      /* if we couldn't match the username and the stun agent has
         IGNORE_CREDENTIALS then we have an integrity check failing.
         This could happen with the race condition of receiving connchecks
         before the remote candidates are added. Just drop the message, and let
         the retransmissions make it work. */
      ICE_DEBUG("Username check failed, agent=%p", agent);
      return ICE_TRUE;
   }

   if (valid != STUN_VALIDATION_SUCCESS) {
      ICE_DEBUG("Agent %p : STUN message is unsuccessfull %d, ignoring", agent, valid);
      return ICE_FALSE;
   }

   ICE_DEBUG("stun message, class=%u",stun_message_get_class (&req));

   if (stun_message_get_class (&req) == STUN_REQUEST) {
      ICE_DEBUG("stun message request, class=%u",stun_message_get_class (&req));
      if ( agent->compatibility == ICE_COMPATIBILITY_MSN || 
           agent->compatibility == ICE_COMPATIBILITY_OC2007) {
         if (local_candidate && remote_candidate2) {
            size_t key_len;
            if (agent->compatibility == ICE_COMPATIBILITY_MSN) {
              username = (uint8_t *) stun_message_find (&req, STUN_ATTRIBUTE_USERNAME, &username_len);
              uname_len = priv_create_username (agent, stream,
                       component->id,  remote_candidate2, local_candidate,
                       uname, sizeof (uname), 0);
              memcpy(username, uname, ICE_MIN (uname_len, username_len));

              req.key = base64_decode ((const unsigned char*) remote_candidate2->password, 
                                       strlen((char *) remote_candidate2->password), &key_len); 
              req.key_len = key_len;
            } else if (agent->compatibility == ICE_COMPATIBILITY_OC2007) {
              req.key = base64_decode ((const unsigned char*) local_candidate->password, 
                                       strlen((char *) local_candidate->password), &key_len);
              req.key_len = key_len;
            }

         } else {
            //Drop request
            ICE_DEBUG("MSN incoming check from unknown remote candidate, agent=%p", agent);
            return ICE_TRUE;
         }
      } // compatibility
      rbuf_len = sizeof (rbuf);

      res = stun_usage_ice_conncheck_create_reply(&component->stun_agent, &req,
              &msg, rbuf, &rbuf_len, &sockaddr.storage, sizeof (sockaddr),
              &control, agent->tie_breaker,
              agent_to_ice_compatibility (agent));

      ICE_DEBUG("ice conncheck, result=%lu",res);

      if ( agent->compatibility == ICE_COMPATIBILITY_MSN
          || agent->compatibility == ICE_COMPATIBILITY_OC2007) {
         free(req.key);
      }

      if (res == STUN_USAGE_ICE_RETURN_ROLE_CONFLICT)
         priv_check_for_role_conflict (agent, control);

      if (res == STUN_USAGE_ICE_RETURN_SUCCESS ||
          res == STUN_USAGE_ICE_RETURN_ROLE_CONFLICT) {
         /* case 1: valid incoming request, send a reply/error */
         int use_candidate = stun_usage_ice_conncheck_use_candidate(&req);
         uint32_t priority = stun_usage_ice_conncheck_priority(&req);
         if (agent->controlling_mode ||
             agent->compatibility == ICE_COMPATIBILITY_GOOGLE ||
             agent->compatibility == ICE_COMPATIBILITY_MSN ||
             agent->compatibility == ICE_COMPATIBILITY_OC2007)
            use_candidate = ICE_TRUE;

         if (stream->initial_binding_request_received != ICE_TRUE)
            agent_signal_initial_binding_request_received(agent, stream);

         if (!list_empty(&component->remote_candidates.list) && remote_candidate == NULL) {
            ICE_ERROR("Agent %p : No matching remote candidate for incoming check ->"
                  "peer-reflexive candidate.", agent);
            remote_candidate = discovery_learn_remote_peer_reflexive_candidate(
                     agent, stream, component, priority, from, nicesock, local_candidate,
                     remote_candidate2 ? remote_candidate2 : remote_candidate);

            if(remote_candidate) {
                if (local_candidate && local_candidate->transport == ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE) {
                   ICE_ERROR("add conn check, foundation=%s(%p)",remote_candidate->foundation, remote_candidate);
                   priv_conn_check_add_for_candidate_pair_matched (agent, stream->id, 
                          component, local_candidate, remote_candidate, ICE_CHECK_DISCOVERED);
                } else {
                   ICE_ERROR("add conn check, foundation=%s(%p)",remote_candidate->foundation, remote_candidate);
                   conn_check_add_for_candidate(agent, stream->id, component, remote_candidate);
                }
            }
         }

         priv_reply_to_conn_check(agent, stream, component, remote_candidate,
             from, nicesock, rbuf_len, rbuf, use_candidate);

         if (list_empty(&component->remote_candidates.list)) {
            /* case: We've got a valid binding request to a local candidate
             *       but we do not yet know remote credentials nor
             *       candidates. As per sect 7.2 of ICE (ID-19), we send a reply
             *       immediately but postpone all other processing until
             *       we get information about the remote candidates */
  
            /* step: send a reply immediately but postpone other processing */
            priv_store_pending_check(agent, component, from, nicesock,
               username, username_len, priority, use_candidate);
         }

      } else {
         ICE_DEBUG("Agent %p : Invalid STUN packet, ignoring it", agent);
         //exit(0);
         return ICE_FALSE;
      }
  } else { // STUN_REQ
      ICE_DEBUG("stun message indication or response or error, class=%u",stun_message_get_class (&req));
      /* case 2: not a new request, might be a reply...  */
      int trans_found = ICE_FALSE;

      /* note: ICE sect 7.1.2. "Processing the Response" (ID-19) */

      /* step: let's try to match the response to an existing check context */
      if (trans_found != ICE_TRUE)
        trans_found = priv_map_reply_to_conn_check_request(agent, stream,
        component, nicesock, from, local_candidate, remote_candidate, &req);
      ICE_DEBUG("processing the response, trans_found=%u",trans_found);

      /* step: let's try to match the response to an existing discovery */
      if (trans_found != ICE_TRUE)
        trans_found = priv_map_reply_to_discovery_request(agent, &req);
      ICE_DEBUG("processing the response, trans_found=%u",trans_found);

      /* step: let's try to match the response to an existing turn allocate */
      ICE_DEBUG("FIXME: priv_map_reply_to_relay_request");
      //if (trans_found != ICE_TRUE)
      //  trans_found = priv_map_reply_to_relay_request (agent, &req);

      /* step: let's try to match the response to an existing turn refresh */
      ICE_DEBUG("FIXME: priv_map_reply_to_relay_refresh");
      //if (trans_found != ICE_TRUE)
      //  trans_found = priv_map_reply_to_relay_refresh (agent, &req);

      /* step: let's try to match the response to an existing keepalive conncheck */
      if (trans_found != ICE_TRUE)
        trans_found = priv_map_reply_to_keepalive_conncheck (agent, component, &req);

      if (trans_found != ICE_TRUE)
        ICE_DEBUG("existing transaction not matched, probably a keepalive, agent=%p", agent);
  }

  return ICE_TRUE;
}

static void
conn_check_stop(agent_t *agent)
{
  ICE_DEBUG("FIXME: conn_check_stop");
  //if (agent->conncheck_timer_source == NULL)
  //  return;

  //g_source_destroy (agent->conncheck_timer_source);
  //g_source_unref (agent->conncheck_timer_source);
  //agent->conncheck_timer_source = NULL;
}


void conn_check_prune_stream(agent_t *agent, stream_t *stream)
{
  stream_t *s = NULL;
  int keep_going = 0;

  ICE_DEBUG("FIXME: freeing conncheck_list of stream, agent=%p,stream=%p", agent, stream);
  if (!TAILQ_EMPTY(&stream->connchecks)) {
  //  g_slist_free_full (stream->conncheck_list, conn_check_free_item);
  //  stream->conncheck_list = NULL;
    TAILQ_INIT(&stream->connchecks);
  }

  TAILQ_FOREACH(s,&agent->streams,list) {
    if (!TAILQ_EMPTY(&s->connchecks)) {
      keep_going = 1;
      break;
    }
  }

  if (!keep_going) {
    ICE_DEBUG("stop conncheck, keep_going=%u",keep_going);
    conn_check_stop(agent);
  }

  return;
}

void
conn_check_free(agent_t *agent) 
{
   //FIXME: free conn check
   return;
}

