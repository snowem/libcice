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

#include <assert.h>

#include "cice/agent.h"
#include "cice/base64.h"
#include "cice/candidate.h"
#include "cice/discovery.h"
#include "cice/network.h"

/* From RFC 5245 section 4.1.3:
 *
 *   for reflexive and relayed candidates, the STUN or TURN servers
 *   used to obtain them have the same IP address.
 */
static int
priv_compare_turn_servers(turnserver_t *turn1, turnserver_t *turn2)
{
   ICE_DEBUG("FIXME: priv_compare_turn_servers");
   return 0;
/*
  if (turn1 == turn2)
    return TRUE;
  if (turn1 == NULL || turn2 == NULL)
    return FALSE;

  return nice_address_equal_no_port (&turn1->server, &turn2->server);
*/
}


static
void priv_generate_candidate_credentials (agent_t *agent,
    candidate_t *candidate)
{
  const char* utemp = "RObomhjs7tw7kmzf";
  const char* ptemp = "jVvUZXC05jO8vi2aqzb7Lerv";
  char *ufrag = NULL;
  char *passwd = NULL;

  if ( agent == NULL || candidate == NULL ) {
     ICE_ERROR("null pointer");
     return;
  }
  ufrag = (char*)malloc(64);
  passwd = (char*)malloc(64);
  if ( ufrag == NULL || passwd == NULL )
     return; 
  memset(ufrag,0,64);
  memset(passwd,0,64);
  //memcpy(ufrag,"peercall",8);
  //memcpy(passwd,"peercall",8);
  memcpy(ufrag,utemp,strlen(utemp));
  memcpy(passwd,ptemp,strlen(ptemp));

  if (agent->compatibility == ICE_COMPATIBILITY_MSN ||
      agent->compatibility == ICE_COMPATIBILITY_OC2007) {

    ICE_FREE(candidate->username);
    ICE_FREE(candidate->password);

    candidate->username = ufrag;
    candidate->password = passwd;
    ICE_DEBUG("FIXME: generating username and pwd, username=%s, password=%s",
          candidate->username, candidate->password);
/*
    char username[32];
    char password[16];
    nice_rng_generate_bytes (agent->rng, 32, (gchar *)username);
    nice_rng_generate_bytes (agent->rng, 16, (gchar *)password);
    candidate->username = g_base64_encode (username, 32);
    candidate->password = g_base64_encode (password, 16);
*/
  } else if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE) {
    //char username[16];

    ICE_FREE(candidate->username);
    ICE_FREE(candidate->password);
    candidate->password = NULL;

    ICE_DEBUG("FIXME: generating username and pwd");
/*
    nice_rng_generate_bytes_print (agent->rng, 16, (gchar *)username);
    candidate->username = g_strndup (username, 16);
*/
  } else {
    candidate->username = ufrag;
    candidate->password = passwd;
    ICE_DEBUG("FIXME: generating username and pwd, username=%s, password=%s",
          candidate->username, candidate->password);
  }

}

/*
 * Assings a foundation to the candidate.
 *
 * Implements the mechanism described in ICE sect
 * 4.1.1.3 "Computing Foundations" (ID-19).
 */
static void priv_assign_foundation (agent_t *agent, candidate_t *candidate)
{
   struct list_head *spos,*cpos,*candpos;

   if ( agent == NULL || candidate == NULL )
      return;

   ICE_DEBUG("priv_assign_foundation");

   list_for_each(spos,&agent->streams.list) {
      stream_t *stream = list_entry(spos,stream_t,list);
      list_for_each(cpos,&stream->components.list) {
         component_t *component = list_entry(cpos,component_t,list);
         list_for_each(candpos,&component->local_candidates.list) {
            candidate_t *n = list_entry(candpos,candidate_t,list);
            assert( candidate != n );

	if (candidate->type == n->type &&
       candidate->transport == n->transport &&
       candidate->stream_id == n->stream_id &&
	    address_equal_no_port (&candidate->base_addr, &n->base_addr) &&
       (candidate->type != ICE_CANDIDATE_TYPE_RELAYED ||
                priv_compare_turn_servers (candidate->turn, n->turn)) &&
       !(agent->compatibility == ICE_COMPATIBILITY_GOOGLE &&
                n->type == ICE_CANDIDATE_TYPE_RELAYED)) {
	  // note: currently only one STUN server per stream at a
	  //       time is supported, so there is no need to check
	  //       for candidates that would otherwise share the
	  //       foundation, but have different STUN servers //
     ICE_DEBUG("copying foundation:%s",candidate->foundation);
	  strncpy(candidate->foundation, n->foundation,
             ICE_CANDIDATE_MAX_FOUNDATION);
          if (n->username) {
            ICE_FREE(candidate->username);
            candidate->username = strdup (n->username);
          }
          if (n->password) {
            ICE_FREE(candidate->password);
            candidate->password = strdup (n->password);
          }
	  return;
	}

         }
      }
   }

  snprintf(candidate->foundation, ICE_CANDIDATE_MAX_FOUNDATION,
      "%u", agent->next_candidate_id++);

  ICE_DEBUG("foundation:%s",candidate->foundation);
  return;
}

/*
 * Adds a new local candidate. Implements the candidate pruning
 * defined in ICE spec section 4.1.3 "Eliminating Redundant
 * Candidates" (ID-19).
 */
static int
priv_add_local_candidate_pruned (agent_t *agent, uint32_t stream_id, 
           component_t *component, candidate_t *candidate)
{
  struct list_head *pos;

  if (candidate == NULL) 
     return ICE_ERR;
 
  list_for_each(pos,&component->local_candidates.list) {
     candidate_t *c = list_entry(pos,candidate_t,list);
    
    ICE_DEBUG("verifying candidate, sid=%u,cid=%u",c->stream_id,c->component_id);
    if (address_equal (&c->base_addr, &candidate->base_addr) &&
        address_equal (&c->addr, &candidate->addr) &&
        c->transport == candidate->transport) {

      ICE_DEBUG("ignoring redundant candidate, candidate=%p,cid=%u", candidate, component->id);
      return ICE_OK;
    }
  }

  ICE_DEBUG("add new candidate, cand=%p",candidate);
  print_candidate(candidate,"new");
  list_add(&candidate->list,&component->local_candidates.list);
  conn_check_add_for_local_candidate(agent, stream_id, component, candidate);

  return ICE_OK;
}



HostCandidateResult 
discovery_add_local_host_candidate (
  agent_t *agent,
  uint32_t stream_id,
  uint32_t component_id,
  address_t *address,
  IceCandidateTransport transport,
  candidate_t **outcandidate)
{
  candidate_t *candidate;
  component_t *component;
  stream_t *stream;
  socket_t *nicesock = NULL;
  HostCandidateResult res = HOST_CANDIDATE_FAILED;

  if (agent_find_component (agent, stream_id, component_id, &stream, &component) != ICE_OK) {
    ICE_DEBUG("no component found, agent=%p,sid=%u,cid=%u", agent,stream_id,component_id);
    return res;
  }

  candidate = candidate_new(ICE_CANDIDATE_TYPE_HOST);
  candidate->transport = transport;
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->base_addr = *address;

  ICE_DEBUG("agent compatibility, compat=%u", agent->compatibility);
  if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = candidate_jingle_priority (candidate);
  } else if (agent->compatibility == ICE_COMPATIBILITY_MSN ||
             agent->compatibility == ICE_COMPATIBILITY_OC2007)  {
    candidate->priority = candidate_msn_priority (candidate);
  } else if (agent->compatibility == ICE_COMPATIBILITY_OC2007R2) {
    candidate->priority =  candidate_ms_ice_priority (candidate,
        agent->reliable, 0);
  } else {
    ICE_DEBUG("using default ice priority, compat=%u", agent->compatibility);
    candidate->priority = candidate_ice_priority (candidate,
        agent->reliable, 0);
  }
  
  priv_generate_candidate_credentials(agent, candidate);
  priv_assign_foundation(agent, candidate);

  /* note: candidate username and password are left NULL as stream
     level ufrag/password are used.*/
  if (transport == ICE_CANDIDATE_TRANSPORT_UDP) {
    nicesock = udp_bsd_socket_new(agent, stream, component, address);
  } else if (transport == ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE) {
    nicesock = tcp_active_socket_new(agent, stream, component, address);
  } else if (transport == ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE) {
    nicesock = tcp_passive_socket_new(agent, stream, component, address);
  } else {
    ICE_ERROR("wrong candidate transport, transport=%u", transport);
  }

  if (!nicesock) {
    res = HOST_CANDIDATE_CANT_CREATE_SOCKET;
    goto errors;
  }


  ICE_DEBUG("local candidate info, sid=%u,fd=%u",stream_id,nicesock->fd);
  print_address(&nicesock->addr);
  candidate->sockptr = nicesock;
  candidate->addr = nicesock->addr;
  candidate->base_addr = nicesock->addr;

  /* check whether a candidate is redundant */
  if (priv_add_local_candidate_pruned 
       (agent, stream_id, component, candidate) != ICE_OK) {
     ICE_DEBUG("got redundant candidate, sid=%u",stream_id);
    res = HOST_CANDIDATE_REDUNDANT;
    goto errors;
  }

  /* _priv_set_socket_tos (agent, nicesock, stream->tos);
  component_attach_socket(component, nicesock); */
  nicesock->component = component;
  component->sock = nicesock;
  *outcandidate = candidate;

  return HOST_CANDIDATE_SUCCESS;


errors:
  if ( candidate )
    candidate_free(candidate);
  if (nicesock)
    socket_free(nicesock);
  return res;
}

static uint32_t priv_highest_remote_foundation (component_t *component)
{
  struct list_head *i;
  uint32_t highest = 1;
  char foundation[ICE_CANDIDATE_MAX_FOUNDATION];

  for (highest = 1;; highest++) {
    int taken = 0;

    snprintf (foundation, ICE_CANDIDATE_MAX_FOUNDATION, "remote-%u",
        highest);
    list_for_each(i,&component->remote_candidates.list) {
      candidate_t *cand = list_entry(i,candidate_t,list);
      if (strncmp (foundation, cand->foundation,
              ICE_CANDIDATE_MAX_FOUNDATION) == 0) {
        taken = 1;
        break;
      }
    }
    if (!taken)
      return highest;
  }

  //g_return_val_if_reached (highest);
  return highest;
}



static void priv_assign_remote_foundation (agent_t *agent, candidate_t *candidate)
{
  struct list_head *i, *j, *k;
  uint32_t next_remote_id;
  component_t *component = NULL;

  list_for_each(i,&agent->streams.list) {
    stream_t *stream = list_entry(i,stream_t,list);
    list_for_each(j,&stream->components.list) {
      component_t *c = list_entry(j,component_t,list);

      if (c->id == candidate->component_id)
        component = c;

      list_for_each(k,&c->remote_candidates.list) {
        candidate_t *n = list_entry(k,candidate_t,list);

        /* note: candidate must not on the remote candidate list */
        if (candidate == n)
           return;

        if (candidate->type == n->type &&
            candidate->transport == n->transport &&
                 candidate->stream_id == n->stream_id &&
          address_equal_no_port (&candidate->addr, &n->addr)) {
          /* note: No need to check for STUN/TURN servers, as these candidate
           * will always be peer reflexive, never relayed or serve reflexive.
           */
          memcpy(candidate->foundation, n->foundation,
                   ICE_CANDIDATE_MAX_FOUNDATION);
          if (n->username) {
            free (candidate->username);
            candidate->username = strdup (n->username);
          }
          if (n->password) {
            free (candidate->password);
            candidate->password = strdup (n->password);
          }
          return;
        }
      }
    }
  }

  if (component) {
    next_remote_id = priv_highest_remote_foundation (component);
    snprintf (candidate->foundation, ICE_CANDIDATE_MAX_FOUNDATION,
        "remote-%u", next_remote_id);
  }
}

/*
 * Adds a new peer reflexive candidate to the list of known
 * remote candidates. The candidate is however not paired with
 * existing local candidates.
 *
 * See ICE sect 7.2.1.3 "Learning Peer Reflexive Candidates" (ID-19).
 *
 * @return pointer to the created candidate, or NULL on error
 */
candidate_t *discovery_learn_remote_peer_reflexive_candidate(
  agent_t *agent, stream_t *stream, component_t *component,
  uint32_t priority, const address_t *remote_address,
  socket_t *nicesock, candidate_t *local, candidate_t *remote)
{
  candidate_t *candidate;

  print_address(remote_address);
  print_candidate(remote, "find candidate");

  candidate = candidate_new(ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
  if ( candidate == NULL )
    return NULL;

  candidate->addr = *remote_address;
  candidate->base_addr = *remote_address;
  if (remote)
    candidate->transport = remote->transport;
  else if (local)
    candidate->transport = conn_check_match_transport(local->transport);
  else {
    if (nicesock->type == ICE_SOCKET_TYPE_UDP_BSD ||
        nicesock->type == ICE_SOCKET_TYPE_UDP_TURN)
      candidate->transport = ICE_CANDIDATE_TRANSPORT_UDP;
    else 
      candidate->transport = ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
  }
  candidate->sockptr = nicesock;
  candidate->stream_id = stream->id;
  candidate->component_id = component->id;

  /* if the check didn't contain the PRIORITY attribute, then the priority will
   * be 0, which is invalid... */
  if (priority != 0) { 
    candidate->priority = priority;
  } else if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = candidate_jingle_priority(candidate);
  } else if (agent->compatibility == ICE_COMPATIBILITY_MSN ||
             agent->compatibility == ICE_COMPATIBILITY_OC2007)  {
    candidate->priority = candidate_msn_priority(candidate);
  } else if (agent->compatibility == ICE_COMPATIBILITY_OC2007R2) {
    candidate->priority =  candidate_ms_ice_priority(candidate,
        agent->reliable, 0);
  } else {
    candidate->priority = candidate_ice_priority(candidate,
        agent->reliable, 0);
  }

  priv_assign_remote_foundation(agent, candidate);

  if ((agent->compatibility == ICE_COMPATIBILITY_MSN ||
       agent->compatibility == ICE_COMPATIBILITY_OC2007) &&
      remote && local) {
    unsigned char *new_username = NULL;
    unsigned char *decoded_local = NULL;
    unsigned char *decoded_remote = NULL;
    size_t local_size;
    size_t remote_size;
    size_t out_size;

    free(candidate->username);
    free (candidate->password);

    decoded_local = base64_decode((const unsigned char*)local->username, 
                                  strlen((const char*)local->username), &local_size);
    decoded_remote = base64_decode((const unsigned char*)remote->username, 
                                   strlen((const char*)remote->username), &remote_size);

    //new_username = g_new0(guchar, local_size + remote_size);
    new_username = (unsigned char*)malloc(local_size + remote_size);
    memcpy(new_username, decoded_remote, remote_size);
    memcpy(new_username + remote_size, decoded_local, local_size);

    candidate->username = base64_encode (new_username, local_size + remote_size, &out_size);
    free(new_username);
    free(decoded_local);
    free(decoded_remote);

    candidate->password = strdup(remote->password);
  } else if (remote) {
    free (candidate->username);
    free (candidate->password);
    candidate->username = strdup(remote->username);
    candidate->password = strdup(remote->password);
  }

  /* note: candidate username and password are left NULL as stream 
     level ufrag/password are used */

  //component->remote_candidates = g_slist_append (component->remote_candidates, candidate);
  list_add(&candidate->list,&component->remote_candidates.list);

  agent_signal_new_remote_candidate (agent, candidate);

  return candidate;
}

/*
 * Creates a peer reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
candidate_t*
discovery_add_peer_reflexive_candidate( agent_t *agent, uint32_t stream_id,
  uint32_t component_id, address_t *address, socket_t *base_socket,
  candidate_t *local, candidate_t *remote)
{
  candidate_t *candidate = 0;
  component_t *component = 0;
  stream_t *stream;
  int result;

  result = agent_find_component(agent, stream_id, component_id, &stream, &component);
  //if (!agent_find_component(agent, stream_id, component_id, &stream, &component)) {
  if (result != ICE_OK) {
    ICE_DEBUG("error in finding component, sid=%u, cid=%u", stream_id, component_id);
    return NULL;
  }

  candidate = candidate_new(ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
  if (local)
    candidate->transport = local->transport;
  else if (remote)
    candidate->transport = conn_check_match_transport(remote->transport);
  else {
    if (base_socket->type == ICE_SOCKET_TYPE_UDP_BSD ||
        base_socket->type == ICE_SOCKET_TYPE_UDP_TURN)
      candidate->transport = ICE_CANDIDATE_TRANSPORT_UDP;
    else
      candidate->transport = ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
  }
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;
  candidate->sockptr = base_socket;
  candidate->base_addr = base_socket->addr;

  ICE_DEBUG("Agent %p : --------------- cand=%p", agent, candidate);

  if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = candidate_jingle_priority(candidate);
  } else if (agent->compatibility == ICE_COMPATIBILITY_MSN ||
             agent->compatibility == ICE_COMPATIBILITY_OC2007)  {
    candidate->priority = candidate_msn_priority(candidate);
  } else if (agent->compatibility == ICE_COMPATIBILITY_OC2007R2) {
    candidate->priority =  candidate_ms_ice_priority(candidate,
        agent->reliable, ICE_FALSE);
  } else {
    candidate->priority = candidate_ice_priority(candidate,
        agent->reliable, ICE_FALSE);
  }

  priv_assign_foundation(agent, candidate);

  if ((agent->compatibility == ICE_COMPATIBILITY_MSN ||
       agent->compatibility == ICE_COMPATIBILITY_OC2007) &&
      remote && local) {
    unsigned char *new_username = NULL;
    unsigned char *decoded_local = NULL;
    unsigned char *decoded_remote = NULL;
    size_t local_size;
    size_t remote_size;
    size_t out_size;
    free(candidate->username);
    free(candidate->password);

    decoded_local = base64_decode((const unsigned char*)local->username, 
                           strlen(local->username), &local_size);
    decoded_remote = base64_decode((const unsigned char*)remote->username, 
                           strlen(remote->username), &remote_size);

    new_username = (unsigned char*)malloc(local_size + remote_size);
    if (new_username == NULL ) {
       ICE_DEBUG("--------------- error in malloc");
       return NULL;
    }
    memset(new_username,0,local_size + remote_size);

    memcpy(new_username, decoded_local, local_size);
    memcpy(new_username + local_size, decoded_remote, remote_size);

    candidate->username = base64_encode ((const unsigned char*)new_username, 
                              local_size + remote_size,&out_size);

    free(new_username);
    free(decoded_local);
    free(decoded_remote);

    candidate->password = strdup(local->password);
  } else if (local) {
    free(candidate->username);
    free(candidate->password);

    candidate->username = strdup(local->username);
    candidate->password = strdup(local->password);
  }

  result = priv_add_local_candidate_pruned(agent, stream_id, component, candidate);
  if (result != ICE_OK) {
    /* error: memory allocation, or duplicate candidate */
    ICE_DEBUG("--------------- error in adding candidate, result=%d", result);
    candidate_free (candidate);
    candidate = NULL;
  }

  return candidate;
}

/*
 * Creates a server reflexive candidate for 'component_id' of stream
 * 'stream_id'.
 *
 * @return pointer to the created candidate, or NULL on error
 */
candidate_t*
discovery_add_server_reflexive_candidate (
  agent_t *agent,
  uint32_t stream_id,
  uint32_t component_id,
  address_t *address,
  IceCandidateTransport transport,
  socket_t *base_socket,
  int nat_assisted)
{
  candidate_t *candidate;
  component_t *component;
  stream_t *stream;
  int result = ICE_FALSE;

  if (!agent_find_component (agent, stream_id, component_id, &stream, &component))
    return NULL;

  candidate = candidate_new(ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
  candidate->transport = transport;
  candidate->stream_id = stream_id;
  candidate->component_id = component_id;
  candidate->addr = *address;

  if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE) {
    candidate->priority = candidate_jingle_priority(candidate);
  } else if (agent->compatibility == ICE_COMPATIBILITY_MSN ||
             agent->compatibility == ICE_COMPATIBILITY_OC2007)  {
    candidate->priority = candidate_msn_priority(candidate);
  } else if (agent->compatibility == ICE_COMPATIBILITY_OC2007R2) {
    candidate->priority =  candidate_ms_ice_priority(candidate,
        agent->reliable, nat_assisted);
  } else {
    candidate->priority =  candidate_ice_priority(candidate,
        agent->reliable, nat_assisted);
  }

  /* step: link to the base candidate+socket */
  candidate->sockptr = base_socket;
  candidate->base_addr = base_socket->addr;

  priv_generate_candidate_credentials(agent, candidate);
  priv_assign_foundation(agent, candidate);

  result = priv_add_local_candidate_pruned(agent, stream_id, component, candidate);
  if (result) {
    agent_signal_new_candidate(agent, candidate);
  }
  else {
    /* error: duplicate candidate */
    candidate_free (candidate);
    candidate = NULL;
  }

  return candidate;
}

/*
 * Creates a server reflexive candidate for 'component_id' of stream
 * 'stream_id' for each TCP_PASSIVE and TCP_ACTIVE candidates for each
 * base address.
 *
 * @return pointer to the created candidate, or NULL on error
 */
void
discovery_discover_tcp_server_reflexive_candidates (
  agent_t *agent, uint32_t stream_id, uint32_t component_id,
  address_t *address, socket_t *base_socket)
{
  component_t *component;
  stream_t *stream;
  address_t base_addr = base_socket->addr;
  struct list_head *i;

  if (!agent_find_component(agent, stream_id, component_id, &stream, &component))
    return;

  address_set_port(&base_addr, 0);
  list_for_each(i,&component->local_candidates.list) {
    candidate_t *c = list_entry(i,candidate_t,list);
    address_t caddr;

    caddr = c->addr;
    address_set_port (&caddr, 0);
    if (c->transport != ICE_CANDIDATE_TRANSPORT_UDP &&
        c->type == ICE_CANDIDATE_TYPE_HOST &&
        address_equal(&base_addr, &caddr)) {
      address_set_port(address, address_get_port (&c->addr));
      discovery_add_server_reflexive_candidate(
          agent,
          stream_id,
          component_id,
          address,
          c->transport,
          (socket_t*)c->sockptr,
          ICE_FALSE);
    }
  }
}

/*
 * Prunes the list of discovery processes for items related
 * to stream 'stream_id'.
 *
 * @return TRUE on success, FALSE on a fatal error
 */
void discovery_prune_stream(agent_t *agent, uint32_t stream_id)
{
  struct list_head *i;

  list_for_each(i,&agent->discovery_list.list) {
    candidate_discovery_t *cand = list_entry(i,candidate_discovery_t,list);
    if (cand->stream->id == stream_id) {
       ICE_DEBUG("FIXME: free discovery list");
      //agent->discovery_list = g_slist_remove (agent->discovery_list, cand);
      //discovery_free_item (cand);
    }
  }

  /* FIXME: free discovery list */
  /*if (agent->discovery_list == NULL) {
    discovery_free (agent);
  }*/
}

void refresh_prune_stream(agent_t *agent, uint32_t stream_id)
{
  struct list_head *i;
  candidate_refresh_t *cand = NULL;

  //list_for_each(i,&agent->refresh_list.list) {
  //  candidate_refresh_t *cand = list_entry(i,candidate_refresh_t,list);
  TAILQ_FOREACH(cand,&agent->refresh_list,list) {

    /* Don't free the candidate refresh to the currently selected local candidate
     * unless the whole pair is being destroyed.
     */
    if (cand->stream->id == stream_id) {
      ICE_DEBUG("FIXME: free refresh list");
      //agent->refresh_list = g_slist_delete_link (agent->refresh_list, i);
      //refresh_free_item (cand);
    }

  }

}

void 
discovery_free_item(candidate_discovery_t *cand)
{
   if (cand) free(cand);
   return;
}

void
discovery_free(agent_t *agent) 
{
  struct list_head *i, *n;

  list_for_each_safe(i,n,&agent->discovery_list.list) {
    candidate_discovery_t *cand = list_entry(i,candidate_discovery_t,list);
    list_del(&cand->list);
    discovery_free_item (cand);
  }


   return;
}

void
refresh_free_item(candidate_refresh_t *cand) 
{
   //FIXME: free item
   return;
}

void
refresh_free(agent_t *agent) 
{
  struct list_head *i, *n;
  candidate_refresh_t *cand = NULL;

  /*list_for_each_safe(i,n,&agent->refresh_list.list) {
    candidate_refresh_t *cand = list_entry(i,candidate_refresh_t,list);
    list_del(&cand->list);
    refresh_free_item (cand);
  }*/

  while (!TAILQ_EMPTY(&agent->refresh_list)) {
    cand = TAILQ_FIRST(&agent->refresh_list);
    TAILQ_REMOVE(&agent->refresh_list, cand, list);
    refresh_free_item (cand);
  }
  return;
}
