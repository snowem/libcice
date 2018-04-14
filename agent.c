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


#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "cice/agent.h"
#include "cice/interfaces.h"
#include "cice/discovery.h"
#include "cice/candidate.h"
#include "cice/network.h"
#include "cice/stun/stunagent.h"

static const char *
_transport_to_string (IceCandidateTransport type) {
  switch(type) {
    case ICE_CANDIDATE_TRANSPORT_UDP:
      return "UDP";
    case ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
      return "TCP-ACT";
    case ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
      return "TCP-PASS";
    case ICE_CANDIDATE_TRANSPORT_TCP_SO:
      return "TCP-SO";
    default:
      return "???";
  }
}


stream_t *
agent_find_stream(agent_t *agent, uint32_t stream_id)
{
   struct list_head *pos;
   stream_t *stream;

   if (agent == NULL)
      return NULL;

   //list_for_each(pos,&agent->streams.list) {
   //   stream = list_entry(pos,stream_t,list);
   TAILQ_FOREACH(stream,&agent->streams,list) {
      //ICE_DEBUG("stream search, id=%u,stream_id=%u",
      //      stream->id,stream_id);
      if (stream->id == stream_id )
         return stream;
   }

   return NULL;
}


int
agent_find_component(agent_t *agent, uint32_t stream_id, uint32_t component_id,
  stream_t **stream, component_t **component)
{
   stream_t *s;
   component_t *c;

   s = agent_find_stream (agent, stream_id);

   if (s == NULL)
      return ICE_NULLPTR;

   c = stream_find_component_by_id (s, component_id);

   if (c == NULL)
      return ICE_NULLPTR;

   if (stream)
      *stream = s;

   if (component)
      *component = c;

   return ICE_OK;
}

agent_t*
ice_agent_new(event_ctx_t *base, IceCompatibility compat, int control_mode) {
   agent_t *agent = NULL;

   agent = (agent_t*)malloc(sizeof(agent_t));
   if (agent == NULL) {
      ICE_ERROR("malloc error, size=%u", sizeof(agent_t));
      return NULL;
   }
   memset(agent,0,sizeof(agent_t));

   /* initialize agent */
   agent->base = base;
   agent->compatibility = compat;
   agent->controlling_mode = control_mode; /* 0 - controlled, 1 - controlling */
   agent->full_mode = 0; 
   agent->next_stream_id = 1;
   agent->use_ice_udp = 1;
   agent->next_candidate_id =1;
   agent->max_conn_checks = 100;
   agent->timer_ta = ICE_AGENT_TIMER_TA_DEFAULT;

   if (base != NULL) {
      agent->base = base;
      base->agent = agent;
   } else {
      ICE_ERROR("no event base");
      free(agent);
      return NULL;
   }

   /*FIXME: get from argument*/
   agent->reliable = 0; 
  
   /* init list of objects */
   TAILQ_INIT(&agent->local_addresses);
   TAILQ_INIT(&agent->streams);       
   INIT_LIST_HEAD(&agent->discovery_list.list);
   TAILQ_INIT(&agent->refresh_list);

   return agent;
}

void
ice_agent_free(agent_t *agent) {
   struct list_head *n,*p;
   stream_t *s = NULL;
   
   discovery_free(agent);
   refresh_free(agent);
   conn_check_free(agent);
   
   /*list_for_each_safe(n,p,&agent->streams.list) {
      stream_t *s = list_entry(n,stream_t,list);
      list_del(&s->list);
      ice_stream_close(s);
   }*/
   while (!TAILQ_EMPTY(&agent->streams)) {
     s = TAILQ_FIRST(&agent->streams);
     TAILQ_REMOVE(&agent->streams, s, list);
     ice_stream_close(s);
   }
   
   if (agent->keepalive_timer_ev) {
      //event_del(agent->keepalive_timer_ev);
      destroy_event_info(agent->base, agent->keepalive_timer_ev);
      agent->keepalive_timer_ev = 0;
   }

   return;
}

int
ice_agent_add_stream(agent_t *agent, uint32_t n_components) {
   stream_t *stream = NULL;

   stream = stream_new(agent,n_components);
   if ( stream == 0 ) {
      ICE_ERROR("failed to create new stream");
      return 0;
   }
   //list_add(&stream->list,&agent->streams.list);
   TAILQ_INSERT_HEAD(&agent->streams,stream,list);

   /*. init components of stream, possibly create pseudo_tcp */
   stream->id = agent->next_stream_id++;
   ICE_INFO("allocating stream, agent=%p, sid=%u(%p),n=%u", 
            agent, stream->id, stream, n_components);
   if (agent->reliable) {
      /* FIXME: create reliable stream 
       * or create pseudo_tcp for each component */
   }

   /* FIXME: use number generator */
   stream_initialize_credentials(stream/*, agent->rng*/); 
    
   return stream->id;
}

int
ice_agent_set_stream_name(agent_t *agent, uint32_t stream_id, const char *name) {
   /* TODO: verify that stream name is valid: audio, video, 
    * text, application, image, message etc, and set stream name */
   return 0;
}

int 
ice_agent_attach_recv (agent_t *agent, uint32_t stream_id, uint32_t component_id,
  agent_recv_func func, void *data) { 
   stream_t *stream;
   component_t *component;
   int ret = 0;

   if (agent == 0) {
      ICE_ERROR("agent is null, sid=%u, cid=%u", stream_id, component_id);
      return ICE_ERR;
   }

   ret = agent_find_component(agent, stream_id, component_id, &stream, &component);
   if (ret != ICE_OK) {
      ICE_ERROR("component not found, ret=%d, sid=%u, cid=%u",
                ret, stream_id, component_id);
      return ICE_ERR;
   }
   
   /* set io callback 'func */
   ICE_INFO("set io callbacks, sid=%u, cid=%u",stream_id,component_id);
   component->io_callback = func;
   component->io_data = data;

   /* Init pseudo_tcp if needed */
   if (agent->reliable && func) {
      /* TODO: init pseudo_tcp */
   }
   
   return 0;
}

void agent_signal_gathering_done(agent_t *agent)
{
   struct list_head *pos;
   stream_t *stream = NULL;

   if (agent == NULL)
      return;

   //list_for_each(pos,&agent->streams.list) {
   //   stream_t *stream = list_entry(pos,stream_t,list);
   TAILQ_FOREACH(stream,&agent->streams,list) {
      if (stream->gathering) {
         stream->gathering = 0;
         if ( agent->candidate_gathering_done_cb ) {
            agent->candidate_gathering_done_cb(agent,
               stream->id,agent->candidate_gathering_done_data);
         }
      }
   }

   return;
}


void 
agent_gathering_done (agent_t *agent) {
   struct list_head *i, *j, *k, *l, *m;
   stream_t *stream = NULL;

   if (agent == NULL)
      return;

   ICE_INFO("gathering done");
   //list_for_each(i,&agent->streams.list) {
   //   stream_t *stream = list_entry(i,stream_t,list);
   TAILQ_FOREACH(stream,&agent->streams,list) {
      list_for_each(j,&stream->components.list) {
         component_t *component = list_entry(j,component_t,list);
         list_for_each(k,&component->local_candidates.list) {
            candidate_t *local_candidate = list_entry(k,candidate_t,list);

            {
               char tmpbuf[INET6_ADDRSTRLEN];
	            address_to_string(&local_candidate->addr, tmpbuf);
               ICE_INFO("Agent %p: gathered %s local candidate : [%s]:%u"
                        " for s%d/c%d. U/P '%s'/'%s'", agent,
                        _transport_to_string (local_candidate->transport),
                        tmpbuf, address_get_port (&local_candidate->addr),
                        local_candidate->stream_id, local_candidate->component_id,
                        local_candidate->username, local_candidate->password);
            }

            list_for_each(l,&component->remote_candidates.list) {
               candidate_t *remote_candidate = list_entry(l,candidate_t,list);
               int found_pair = 0;

               list_for_each(m,&stream->connchecks.list) {
                  candidate_check_pair_t *p = list_entry(m,candidate_check_pair_t,list);
                  if (p->local == local_candidate && p->remote == remote_candidate) {
                     found_pair = 1;
                     break;
                  }
               }
               if (!found_pair) {
                 ICE_ERROR("add candidate pair, found_pair=%u, foundation=%s(%p)",
                           found_pair,remote_candidate->foundation, remote_candidate);
                 conn_check_add_for_candidate_pair(agent, stream->id, component,
                     local_candidate, remote_candidate);
               }

            }
         }
      }
   }

   /* FIXME: discovery timer */
   //if (agent->discovery_timer_source == NULL)
      agent_signal_gathering_done(agent);

   return;
}


int
ice_agent_gather_candidates (agent_t *agent, uint32_t stream_id) {
   stream_t *stream;
   address_head_t local_addresses;
   address_head_t *head = NULL;
   address_t *addr = NULL;
   uint32_t cid;
   int get_local_address = 0;
   int ret = ICE_OK;

   TAILQ_INIT(&local_addresses);

   if ( agent == NULL )
      return ICE_NULLPTR;

   if ( stream_id <= 0 ) 
      return ICE_ERR;

   stream = agent_find_stream(agent,stream_id);
   if ( stream == NULL )
      return ICE_ERR;

   /* Ignore if gathering candidates is started */
   if ( stream->gathering_started ) 
      return ICE_OK;

   ICE_DEBUG("starting candidate gathering, agent=%p, mode=%s", 
        agent, agent->full_mode ? "ICE-FULL" : "ICE-LITE");   

   /* If no local addresses in streams, then generates the list */
   if (TAILQ_EMPTY(&agent->local_addresses)) {
      ICE_INFO("no local addresses gathered, agent=%p", agent);
      ice_interfaces_get_local_ips(&local_addresses,0);
      head = &local_addresses;
      get_local_address = 1;
   } else {
      head = &agent->local_addresses;
   }

   while (!TAILQ_EMPTY(head)) {
      candidate_t *host_candidate;
      addr = TAILQ_FIRST(head);
      TAILQ_REMOVE(head, addr, list);

      print_address(addr);

      for (cid = 1; cid <= stream->n_components; cid++) { 
         int add_type;

         component_t *component = stream_find_component_by_id (stream, cid);
         if (component == NULL ) {
            ICE_ERROR("component not found, cid=%u",cid);
            continue;
         }
         for (add_type=ADD_HOST_MIN; add_type<=ADD_HOST_MAX; add_type++) {
            HostCandidateResult res = HOST_CANDIDATE_CANT_CREATE_SOCKET;
            IceCandidateTransport transport;
            uint16_t current_port;
            uint16_t start_port;

            /* TODO: currently support udp, need tcp */
            if ((!agent->use_ice_udp && add_type == ADD_HOST_UDP) ||
                (!agent->use_ice_tcp && add_type != ADD_HOST_UDP))
              continue;

            switch (add_type) {
              default:
              case ADD_HOST_UDP:
                transport = ICE_CANDIDATE_TRANSPORT_UDP;
                break;
              case ADD_HOST_TCP_ACTIVE:
                transport = ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
                break;
              case ADD_HOST_TCP_PASSIVE:
                transport = ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
                break;
            }
            start_port = component->min_port;
            if(component->min_port != 0) {
              //start_port = nice_rng_generate_int(agent->rng, 
              //         component->min_port, component->max_port+1);
              /*FIXME: impl rng algorithm */
              start_port = 10000;
            }
            current_port = start_port;

            /* Generate the list of host candidate */
            host_candidate = NULL;
            while (res == HOST_CANDIDATE_CANT_CREATE_SOCKET) {
              ICE_DEBUG("trying to create host candidate, agent=%p, port=%u", agent, current_port);
              address_set_port (addr, current_port);
              res = discovery_add_local_host_candidate(agent, stream->id, cid,
                  addr, transport, &host_candidate);
              if (current_port > 0)
                 current_port++;
              if (current_port > component->max_port) 
                 current_port = component->min_port;
              if (current_port == 0 || current_port == start_port)
                 break;
            }

            if (res == HOST_CANDIDATE_REDUNDANT) {
               ICE_DEBUG("ignoring local redundant candidate, agent=%p", agent);
               continue;
            } else if (res == HOST_CANDIDATE_FAILED) {
               ICE_DEBUG("could not retrieive component, agent=%p, sid=%u, cid=%u", 
                         agent,stream->id,cid);
               ret = ICE_ERR;
               goto error;
            } else if (res == HOST_CANDIDATE_CANT_CREATE_SOCKET) {
              {// print debug info
                char ip[ICE_ADDRESS_STRING_LEN];
                address_to_string (addr, ip);
                ICE_ERROR("unable to add local host candidate, agent=%p, ip=%s, sid=%u, cid=%u", 
                          agent, ip, stream->id, component->id);
              }
              ret = ICE_ERR;
              goto error;
            }

            address_set_port(addr, 0);
            if (agent->reliable) {
               /* TODO: set writable callback for socket */
            }

            /* Discovery reflecxive candidates via stun protocol */
            if (agent->full_mode && agent->stun_server_ip &&
               transport == ICE_CANDIDATE_TRANSPORT_UDP) {
               /* TODO: Add server-reflexive support for TCP candidates */
               //priv_add_new_candidate_discovery_stun();
            }

            //5. Discovery relayed candidates via turn protocol.
            if (agent->full_mode && component &&
               transport != ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE) {
               /* TODO: Add support for relay candidates */
               //priv_add_new_candidate_discovery_turn();
            }

         }
      }
      if (get_local_address);
        address_free(addr);
   }
  
   stream->gathering = 1;
   stream->gathering_started = 1; 
  
   for (cid = 1; cid <= stream->n_components; cid++) {
      component_t *component = stream_find_component_by_id(stream, cid);
      struct list_head *pos;
      list_for_each(pos,&component->local_candidates.list) {
         candidate_t *c = list_entry(pos,candidate_t,list);
         //agent_signal_new_candidate
         /* TODO: call 'new candidate' callback */
         print_address(&c->addr);
      }
   }
  
   ICE_DEBUG("starting discovery process, discovery_unsched_items=%u",
             agent->discovery_unsched_items);
   if (agent->discovery_unsched_items == 0) {
      /* Calls "gathering done" callback if needed */
      agent_gathering_done(agent);
   } else if (agent->discovery_unsched_items) {
      /* TODO: Setup timers and initiate the candidate discovery process */
      //discovery_schedule(agent);
   }

   //9. Handling error
error:  
   if (ret != ICE_OK ) {
      for (cid = 1; cid <= stream->n_components; cid++) {
         struct list_head *pos,*n;
         component_t *component = stream_find_component_by_id(stream, cid);
         list_for_each_safe(pos,n,&component->local_candidates.list) {
            //candidate_t *c = list_entry(pos,candidate_t,list);
            //agent_remove_local_candidate(agent, c);
            //INIT_LIST_HEAD(&component->local_candidates.list);
            /* TODO: remove local candidate */
            list_del(pos);
         }
      }
      /* TODO: stop discovery process */
      //discovery_prune_stream(agent, stream_id);
   }
   return ret;
}

void
ice_set_candidate_gathering_done_cb(agent_t *agent, candidate_gathering_done_func cb, void *data) {
   if (agent==NULL)
      return;

   agent->candidate_gathering_done_cb = cb;
   agent->candidate_gathering_done_data = data;
   return;
}

void
ice_set_component_state_changed_cb(agent_t *agent, component_state_changed_func cb, void *data) {
   if (agent==NULL)
      return;

   agent->component_state_changed_cb = cb;
   agent->component_state_changed_data = data;
   return;
}

void
ice_set_new_selected_pair_cb(agent_t *agent, new_selected_pair_func cb, void *data) {
   if (agent==NULL)
      return;

   agent->new_selected_pair_cb = cb;
   agent->new_selected_pair_data = data;
   return;
}

void
ice_set_new_remote_candidate_cb(agent_t *agent, new_remote_candidate_func cb, void *data) {
   if (agent==NULL)
      return;

   agent->new_remote_candidate_cb = cb;
   agent->new_remote_candidate_data = data;
   return;
}

void
ice_agent_init_stun_agent (agent_t *agent, struct stun_agent_t *stun_agent) {
  if (agent->compatibility == ICE_COMPATIBILITY_GOOGLE) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_IGNORE_CREDENTIALS);
  } else if (agent->compatibility == ICE_COMPATIBILITY_MSN) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_FORCE_VALIDATER);
  } else if (agent->compatibility == ICE_COMPATIBILITY_WLM2009) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_WLM2009,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_USE_FINGERPRINT);
  } else if (agent->compatibility == ICE_COMPATIBILITY_OC2007) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_FORCE_VALIDATER |
        STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
  } else if (agent->compatibility == ICE_COMPATIBILITY_OC2007R2) {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_WLM2009,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_USE_FINGERPRINT |
        STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
  } else {
    stun_agent_init (stun_agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC5389,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_USE_FINGERPRINT);
  }
  stun_agent_set_software(stun_agent, agent->software_attribute);
  return;
}

uint64_t
agent_candidate_pair_priority(agent_t *agent, candidate_t *local, candidate_t *remote) {
  uint64_t prio = 0;
  if (agent->controlling_mode)
    prio = candidate_pair_priority(local->priority, remote->priority);
  else
    prio = candidate_pair_priority(remote->priority, local->priority);

  return prio;
}

const char*
component_state_to_string(IceComponentState state) {
   switch (state)
   {
      case ICE_COMPONENT_STATE_DISCONNECTED:
        return "disconnected";
      case ICE_COMPONENT_STATE_GATHERING:
        return "gathering";
      case ICE_COMPONENT_STATE_CONNECTING:
        return "connecting";
      case ICE_COMPONENT_STATE_CONNECTED:
        return "connected";
      case ICE_COMPONENT_STATE_READY:
        return "ready";
      case ICE_COMPONENT_STATE_FAILED:
        return "failed";
      case ICE_COMPONENT_STATE_LAST:
      default:
        return "invalid";
   }
   return "invalid";
}


void agent_signal_component_state_change(agent_t *agent, 
     uint32_t stream_id, uint32_t component_id, IceComponentState state) {
   component_t *component;
   stream_t *stream;

   //ICE_DEBUG("component state change, newstate=%u", state);
   if (agent == NULL)
      return;

   if (agent_find_component(agent, stream_id, component_id,
          &stream, &component) != ICE_OK)
      return;

   ICE_DEBUG("component state change, oldstate=%u,newstate=%u",
             component->state,state);

  if (component->state != state && state < ICE_COMPONENT_STATE_LAST) {
    ICE_DEBUG("STATE-CHANGE , sid=%u, cid=%u, old=%s, new=%s",
              stream_id, component_id, 
              component_state_to_string(component->state),
              component_state_to_string (state));
    component->state = state;

    /* FIXME: reliable agent check */
    /*if (agent->reliable)
      process_queued_tcp_packets (agent, stream, component);*/

    if ( agent->component_state_changed_cb )
       agent->component_state_changed_cb(agent,stream_id,component_id,
                            state,agent->component_state_changed_data);
  }

  return;
}

int
ice_agent_get_selected_pair (agent_t *agent, uint32_t stream_id,
    uint32_t component_id, candidate_t **local, candidate_t **remote)
{
  component_t *component;
  stream_t *stream;
  int ret = ICE_ERR;

  ICE_DEBUG("getting selected pair, sid=%u, cid=%u, local=%p, remote=%p",
            stream_id, component_id, local, remote);
  if (stream_id < 1 || component_id < 1 || local == NULL || remote == NULL ) {
    ICE_DEBUG("error in getting selected pair, sid=%u, cid=%u, local=%p, remote=%p",
              stream_id, component_id, local, remote);
    return ret;
  }

  /* step: check that params specify an existing pair */
  ret = agent_find_component (agent, stream_id, component_id, &stream, &component);
  if (ret != ICE_OK) {
    ICE_DEBUG("pair selected not found, sid=%u, cid=%u, ret=%d",stream_id,component_id,ret);
    goto done;
  }

  ICE_DEBUG("error in getting selected pair, c=%p, local=%p, remote=%p",
            component,
            component->selected_pair.local,
            component->selected_pair.remote);

  if (component->selected_pair.local && component->selected_pair.remote) {
    *local = component->selected_pair.local;
    *remote = component->selected_pair.remote;
    ICE_DEBUG("get selected pair, local=%p, remote=%p", *local, *remote);
    ret = ICE_OK;
  }

  ICE_DEBUG("error in getting selected pair, sid=%u, cid=%u, local=%p, remote=%p",
            stream_id, component_id, local, remote);

done:
  return ret;
}

int
ice_agent_get_local_credentials(agent_t *agent, uint32_t stream_id, 
     char **ufrag, char **pwd) {
  stream_t *stream;
  int ret = ICE_OK;

  if ( agent == NULL || stream_id < 1 )
     return ICE_ERR;

  stream = agent_find_stream (agent, stream_id);
  if (stream == NULL) {
    goto done;
  }

  if (!ufrag || !pwd) {
    goto done;
  }

  *ufrag = strdup (stream->local_ufrag);
  *pwd = strdup (stream->local_password);
  ret = ICE_OK;

done:
  return ret;
}

candidate_t*
ice_agent_get_local_candidates(agent_t *agent, uint32_t stream_id, uint32_t component_id)
{
  component_t *component;
  candidate_t *ret = NULL;
  struct list_head *pos;

  if (agent == NULL || stream_id < 1 || component_id < 1) {
     return NULL;
  }

  if (agent_find_component (agent, stream_id, component_id, NULL, &component) != ICE_OK) {
    goto done;
  }

  ret = candidate_new(ICE_CANDIDATE_TYPE_LAST);
  if ( ret == NULL )
     return NULL;

  list_for_each(pos,&component->local_candidates.list) {
     candidate_t *c = list_entry(pos,candidate_t,list);
     candidate_t *copy = candidate_copy(c);
     if ( copy != NULL )
       list_add(&copy->list,&ret->list) ;
  }

done:
  return ret;
}

int
ice_agent_set_remote_credentials(agent_t *agent, uint32_t stream_id, 
            const char *ufrag, const char *pwd)
{
  stream_t *stream;
  int ret = ICE_ERR;

  if (agent == NULL || stream_id < 1) 
     return ICE_ERR;

  stream = agent_find_stream(agent, stream_id);
  if (stream && ufrag && pwd) {
    strncpy(stream->remote_ufrag, ufrag, ICE_STREAM_MAX_UFRAG);
    strncpy(stream->remote_password, pwd, ICE_STREAM_MAX_PWD);
    ret = ICE_OK;
  }

  return ret;
}

static int
priv_add_remote_candidate( agent_t *agent, uint32_t stream_id,
     uint32_t component_id, IceCandidateType type,
     const address_t *addr, const address_t *base_addr,
     IceCandidateTransport transport, uint32_t priority,
     const char *username, const char *password,
     const char *foundation) {
  component_t *component;
  candidate_t *candidate;

  if (agent_find_component (agent, stream_id, component_id, NULL, &component) != ICE_OK)
    return ICE_ERR;

  candidate = component_find_remote_candidate(component, addr, transport);

  if (candidate && candidate->type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE && 
      candidate->priority == priority ) {
     ICE_ERROR("updating existing peer-rfx remote candidate, type=%u, foundation=%s(%p)", 
               type, candidate->foundation, candidate);
     candidate->type = type;
  }

  if (candidate && candidate->type == type) {
    {
      char tmpbuf[INET6_ADDRSTRLEN] = {0};
      address_to_string (addr, tmpbuf);
      ICE_ERROR("remote candidate exists, addr=%s:%u, sid=%u, cid=%u,"
          " username=%s, pass=%s prio=%u, foundation=%s", tmpbuf,
          address_get_port (addr), stream_id, component_id,
          username, password, priority, foundation);
    }
    /* an existing candidate, update the attributes */
    candidate->type = type;
    if (base_addr)
       candidate->base_addr = *base_addr;
    candidate->priority = priority;
    if (foundation) {
       ICE_ERROR("new foundation, old=%s, new=%s(%p)", candidate->foundation, foundation, candidate);
       strncpy(candidate->foundation, foundation, ICE_CANDIDATE_MAX_FOUNDATION);
    }
    if (username) {
       free(candidate->username);
       candidate->username = strdup(username);
    }
    if (password) {
       free(candidate->password);
       candidate->password = strdup(password);
    }
  }
  else {
    /* add a new candidate */
    if (type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
      ICE_DEBUG("ignoring peer-reflexive candidate");
      return ICE_ERR;
    }
    candidate = candidate_new(type);
    list_add(&candidate->list,&component->remote_candidates.list);

    candidate->stream_id = stream_id;
    candidate->component_id = component_id;
    candidate->type = type;
    if (addr)
      candidate->addr = *addr;

    {
      char tmpbuf[INET6_ADDRSTRLEN] = {0};
      if (addr) address_to_string (addr, tmpbuf);
      ICE_DEBUG("new remote candidate, type=%s, addr=%s:%u"
          " sid=%d, cid=%d, username=%s, pass=%s, prio=%u",
          _transport_to_string (transport), tmpbuf,
          addr? address_get_port (addr) : 0, stream_id, 
          component_id, username, password, priority);
    }

    if (base_addr)
       candidate->base_addr = *base_addr;

    candidate->transport = transport;
    candidate->priority = priority;
    if (username) candidate->username = strdup(username);
    if (password) candidate->password = strdup(password);

    if (foundation) {
       strncpy(candidate->foundation, foundation,
               ICE_CANDIDATE_MAX_FOUNDATION);
    }
  }

  if (conn_check_add_for_candidate(agent, stream_id, component, candidate) < 0) {
    goto errors;
  }

  return ICE_OK;

errors:
  ICE_ERROR("got error");
  candidate_free(candidate);
  return ICE_ERR;
}


static int
_set_remote_candidates_locked(agent_t *agent, stream_t *stream,
     component_t *component, const candidate_t *candidates) {
  struct list_head *pos;
  int added = 0;

  list_for_each(pos,&candidates->list) {
     candidate_t *d = list_entry(pos,candidate_t,list);
     {
      char tmpbuf[INET6_ADDRSTRLEN];
      address_to_string (&d->addr, tmpbuf);
      ICE_DEBUG("remote candidate, addr:%s, port:%u, foundation=%s(%p)", 
                tmpbuf, address_get_port(&d->addr), d->foundation, d);
     }

     if (address_is_valid(&d->addr)) {
        int res = priv_add_remote_candidate(
              agent,
              stream->id,
              component->id,
              d->type,
              &d->addr,
              &d->base_addr,
              d->transport,
              d->priority,
              d->username,
              d->password,
              d->foundation);
        if (res == ICE_OK)
          ++added;
     }
  }

  conn_check_remote_candidates_set(agent);

  ICE_DEBUG("schedule any conn checks, added=%u", added);
  if (added > 0) {
    int res = conn_check_schedule_next(agent);
    if (res != ICE_TRUE)
      ICE_ERROR("unable to schedule any conn checks, res=%u", res);
  }

  return added;
}


int
ice_agent_set_remote_candidates(agent_t *agent, uint32_t stream_id, 
   uint32_t component_id, const candidate_t *candidates)
{
  int added = 0;
  stream_t *stream;
  component_t *component;

  if ( agent == NULL || stream_id < 1 || component_id < 1 ) {
     return added;
  }

  ICE_DEBUG("set_remote_candidates, sid=%d, cid=%d", stream_id, component_id);

  if (agent_find_component(agent, stream_id, component_id,
          &stream, &component) != ICE_OK) {
    ICE_ERROR("Could not find component %u in stream %u", component_id, stream_id);
    added = -1;
    goto done;
  }

  added = _set_remote_candidates_locked(agent, stream, component, candidates);
  
  ICE_DEBUG("pair added, added=%u",added);
done:
  return added;
}

void 
agent_signal_new_selected_pair (agent_t *agent, uint32_t stream_id,
    uint32_t component_id, candidate_t *lcandidate, candidate_t *rcandidate)
{
  component_t *component;
  stream_t *stream;

  if (agent_find_component(agent, stream_id, component_id,
      &stream, &component) != ICE_OK)
     return;

  if (((socket_t *)lcandidate->sockptr)->type == ICE_SOCKET_TYPE_UDP_TURN) {
      /*FIXME: not support upd-turn */
     //nice_udp_turn_socket_set_peer (lcandidate->sockptr, &rcandidate->addr);
  }

  /*FIXME: not suport reliable socket */
  /*if(agent->reliable && !nice_socket_is_reliable (lcandidate->sockptr)) {
    if (!component->tcp)
      pseudo_tcp_socket_create (agent, stream, component);
    process_queued_tcp_packets (agent, stream, component);

    pseudo_tcp_socket_connect (component->tcp);
    pseudo_tcp_socket_notify_mtu (component->tcp, MAX_TCP_MTU);
    adjust_tcp_clock (agent, stream, component);
  }*/

  {
    char ip[100];
    uint32_t port;

    port = address_get_port (&lcandidate->addr);
    address_to_string (&lcandidate->addr, ip);

    ICE_DEBUG("Local selected pair: %d:%d %s %s %s:%d %s",
        stream_id, component_id, lcandidate->foundation,
        lcandidate->transport == ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE ?
        "TCP-ACT" :
        lcandidate->transport == ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE ?
        "TCP-PASS" :
        lcandidate->transport == ICE_CANDIDATE_TRANSPORT_UDP ? "UDP" : "???",
        ip, port, lcandidate->type == ICE_CANDIDATE_TYPE_HOST ? "HOST" :
        lcandidate->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ?
        "SRV-RFLX" :
        lcandidate->type == ICE_CANDIDATE_TYPE_RELAYED ?
        "RELAYED" :
        lcandidate->type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE ?
        "PEER-RFLX" : "???");

    port = address_get_port (&rcandidate->addr);
    address_to_string (&rcandidate->addr, ip);

    ICE_DEBUG("Remote selected pair: %d:%d %s %s %s:%d %s",
        stream_id, component_id, rcandidate->foundation,
        rcandidate->transport == ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE ?
        "TCP-ACT" :
        rcandidate->transport == ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE ?
        "TCP-PASS" :
        rcandidate->transport == ICE_CANDIDATE_TRANSPORT_UDP ? "UDP" : "???",
        ip, port, rcandidate->type == ICE_CANDIDATE_TYPE_HOST ? "HOST" :
        rcandidate->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ?
        "SRV-RFLX" :
        rcandidate->type == ICE_CANDIDATE_TYPE_RELAYED ?
        "RELAYED" :
        rcandidate->type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE ?
        "PEER-RFLX" : "???");
  }

  /* FIXME: send signal and call callbacks: pair full or not */
  if (agent->new_selected_pair_cb ) {
     agent->new_selected_pair_cb(agent,stream_id, component_id, 
        lcandidate->foundation, rcandidate->foundation,agent->new_selected_pair_data);
  }
/*
  agent_queue_signal (agent, signals[SIGNAL_NEW_SELECTED_PAIR_FULL],
      stream_id, component_id, lcandidate, rcandidate);
  agent_queue_signal (agent, signals[SIGNAL_NEW_SELECTED_PAIR],
      stream_id, component_id, lcandidate->foundation, rcandidate->foundation);

  if(agent->reliable && nice_socket_is_reliable (lcandidate->sockptr)) {
    agent_signal_socket_writable (agent, component);
  }
*/
   return;
}

/* Helper function to allow us to send connchecks reliably.
 * If the transport is reliable, then we request a reliable send, which will
 * either send the data, or queue it in the case of unestablished http/socks5
 * proxies or tcp-turn. If the transport is not reliable, then it could be an
 * unreliable tcp-bsd, so we still try a reliable send to see if it can succeed
 * meaning the message was queued, or if it failed, then it was either udp-bsd
 * or turn and so we retry with a non reliable send and let the retransmissions
 * take care of the rest.
 * This is in order to avoid having to retransmit something if the underlying
 * socket layer can queue the message and send it once a connection is
 * established.
 */
int
agent_socket_send(socket_t *sock, const address_t *addr, 
    const char *buf, uint32_t len)
{
   int n = 0;;

   if ( sock == NULL )
      return 0;

   /*FIXME: socket reliable */
   switch(sock->type) {
      case ICE_SOCKET_TYPE_UDP_BSD: 
      {
         n = udp_socket_send(sock,addr,buf,len);
         break;
      }
      case ICE_SOCKET_TYPE_TCP_ACTIVE:
      {
         n = tcp_active_socket_send(sock,addr,len,buf);
         break;
      }
      case ICE_SOCKET_TYPE_TCP_PASSIVE:
      {
         n = tcp_passive_socket_send(sock,addr,len,buf);
         break;
      }
      default:
      {
         ICE_ERROR("unknown socket type, type=%u",sock->type);
         break;
      }
   }

   return n;
}

StunUsageIceCompatibility
agent_to_ice_compatibility (agent_t *agent) 
{   
  return agent->compatibility == ICE_COMPATIBILITY_GOOGLE ?
      STUN_USAGE_ICE_COMPATIBILITY_GOOGLE :
      agent->compatibility == ICE_COMPATIBILITY_MSN ?
      STUN_USAGE_ICE_COMPATIBILITY_MSN :
      agent->compatibility == ICE_COMPATIBILITY_WLM2009 ?
      STUN_USAGE_ICE_COMPATIBILITY_WLM2009 :   
      agent->compatibility == ICE_COMPATIBILITY_OC2007 ?
      STUN_USAGE_ICE_COMPATIBILITY_MSN :
      agent->compatibility == ICE_COMPATIBILITY_OC2007R2 ?
      STUN_USAGE_ICE_COMPATIBILITY_WLM2009 :
      STUN_USAGE_ICE_COMPATIBILITY_RFC5245;
}

void agent_signal_initial_binding_request_received(agent_t *agent, stream_t *stream)
{ 
  if (stream->initial_binding_request_received != ICE_TRUE) {
    stream->initial_binding_request_received = ICE_TRUE;
    /* FIXME: send signal initial_binding_request_received */
    //agent_queue_signal (agent, signals[SIGNAL_INITIAL_BINDING_REQUEST_RECEIVED], stream->id);
  }
}  

void agent_signal_new_candidate(agent_t *agent, candidate_t *candidate)
{
  /* FIXME: agent_signal_new_candidate */
  /*agent_queue_signal (agent, signals[SIGNAL_NEW_CANDIDATE_FULL],
      candidate);
  agent_queue_signal (agent, signals[SIGNAL_NEW_CANDIDATE],
      candidate->stream_id, candidate->component_id, candidate->foundation);*/
}

void agent_signal_new_remote_candidate(agent_t *agent, candidate_t *candidate)
{
   /* FIXME: agent_signal_new_remote_candidate */
   if (agent == NULL)
      return;

   if ( agent->new_remote_candidate_cb ) {
      //ICE_DEBUG("call new_remote_candidate_cb");
      agent->new_remote_candidate_cb(agent,candidate->stream_id, 
            candidate->component_id, candidate->foundation,
            agent->new_remote_candidate_data);
   }
   /*agent_queue_signal (agent, signals[SIGNAL_NEW_REMOTE_CANDIDATE_FULL],
      candidate);
   agent_queue_signal (agent, signals[SIGNAL_NEW_REMOTE_CANDIDATE],
      candidate->stream_id, candidate->component_id, candidate->foundation);*/
}

/* Create a new timer GSource with the given @name, @interval, callback
 * @function and @data, and assign it to @out, destroying and freeing any
 * existing #GSource in @out first.
 *
 * This guarantees that a timer won’t be overwritten without being destroyed.
 */
void agent_timeout_add_with_context (agent_t *agent, void **out,
    const char *name, uint32_t interval, void *function, void *data)
{
   /* FIXME agent_timeout_add_with_context */
/*
  GSource *source;

  g_return_if_fail (function != NULL);
  g_return_if_fail (out != NULL);

  // Destroy any existing source. //
  if (*out != NULL) {
    g_source_destroy (*out);
    g_source_unref (*out);
    *out = NULL;
  }

  // Create the new source. //
  source = g_timeout_source_new (interval);

  g_source_set_name (source, name);
  g_source_set_callback (source, function, data, NULL);
  g_source_attach (source, agent->main_context);

  // Return it! //
  *out = source;
*/
  return;
}

int
ice_agent_send(agent_t *agent, uint32_t stream_id, uint32_t component_id,
  const char *buf, uint32_t len)
{
   stream_t *stream;
   component_t *component;
   int n = 0;

   if (agent == NULL || stream_id < 1 || component_id < 1 || buf == NULL)
      return ICE_ERR;

   if (agent_find_component (agent, stream_id, component_id, &stream, &component) != ICE_OK) {
      ICE_DEBUG("Invalid stream or component, sid=%u,cid=%u",stream_id,component_id);
      goto done;
   }

   if (component->selected_pair.local != NULL) {
      {
         char tmpbuf[INET6_ADDRSTRLEN];
         char tmpbuf1[INET6_ADDRSTRLEN];
         address_to_string (&component->selected_pair.remote->addr, tmpbuf);
         address_to_string (&component->selected_pair.local->addr, tmpbuf1);

         ICE_DEBUG("sending message, sid=%u, cid=%u, from [%s]:%d to "
               "[%s]:%d", stream_id, component_id, 
               tmpbuf1, address_get_port (&component->selected_pair.local->addr), 
               tmpbuf, address_get_port (&component->selected_pair.remote->addr));
      }

      if(agent->reliable 
         /*&& !socket_is_reliable (component->selected_pair.local->sockptr)*/) {
         /* FIXME: Send on the pseudo-TCP socket */
      } else {
         socket_t *sock;
         address_t *addr;

         sock = (socket_t*)component->selected_pair.local->sockptr;
         addr = &component->selected_pair.remote->addr;

         if (socket_is_reliable(sock)) {
            /* FIXME: support ice-tcp */
         } else {
            n = udp_socket_send(sock, addr, buf, len);
         }

         if (n < 0) {
            ICE_DEBUG("failed to send msg, n=%d",n);
         }
      }

   } else { // not have selected local
      ICE_ERROR("no selected pair, sid=%u, cid=%u",stream_id,component_id);
   }

done:

   return n;
/*
  n_sent_bytes = nice_agent_send_messages_nonblocking_internal (agent,
      stream_id, component_id, &local_message, 1, TRUE, NULL);
*/
}

int
ice_agent_add_local_address (agent_t *agent, address_t *addr)
{
  address_t *dupaddr;

  if (agent == NULL || addr == NULL)
     return ICE_ERR;

  dupaddr = address_dup(addr);
  address_set_port (dupaddr, 0);
  TAILQ_INSERT_HEAD(&agent->local_addresses,dupaddr,list);

  return ICE_OK;
}

int
ice_agent_set_relay_info(agent_t *agent,
    uint32_t stream_id, uint32_t component_id,
    const char *server_ip, uint32_t server_port,
    const char *username, const char *password,
    IceRelayType type)
{
   /* FIXME: setup relay info */
/*
  component_t *component = NULL;
  stream_t *stream = NULL;
  int ret = ICE_TRUE;
  TurnServer *turn;

  g_return_val_if_fail (NICE_IS_AGENT (agent), FALSE);
  g_return_val_if_fail (stream_id >= 1, FALSE);
  g_return_val_if_fail (component_id >= 1, FALSE);
  g_return_val_if_fail (server_ip, FALSE);
  g_return_val_if_fail (server_port, FALSE);
  g_return_val_if_fail (username, FALSE);
  g_return_val_if_fail (password, FALSE);
  g_return_val_if_fail (type <= NICE_RELAY_TYPE_TURN_TLS, FALSE);

  agent_lock();

  if (!agent_find_component (agent, stream_id, component_id, &stream,
          &component)) {
    ret = FALSE;
    goto done;
  }

  turn = turn_server_new (server_ip, server_port, username, password, type);

  if (!turn) {
    ret = FALSE;
    goto done;
  }

  nice_debug ("Agent %p: added relay server [%s]:%d of type %d to s/c %d/%d "
      "with user/pass : %s -- %s", agent, server_ip, server_port, type,
      stream_id, component_id, username, password);

  component->turn_servers = g_list_append (component->turn_servers, turn);

 if (stream->gathering_started) {
    GSList *i;

    stream->gathering = TRUE;

    for (i = component->local_candidates; i; i = i->next) {
      NiceCandidate *candidate = i->data;

      if  (candidate->type == NICE_CANDIDATE_TYPE_HOST &&
           candidate->transport != NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE)
        priv_add_new_candidate_discovery_turn (agent,
            candidate->sockptr, turn, stream, component_id,
            candidate->transport != NICE_CANDIDATE_TRANSPORT_UDP);
    }

    if (agent->discovery_unsched_items)
      discovery_schedule (agent);
  }


 done:

  agent_unlock_and_emit (agent);
  return ret;
*/
  return 0;
}

void
ice_agent_set_port_range(agent_t *agent, uint32_t stream_id, uint32_t component_id,
    uint32_t min_port, uint32_t max_port)
{
  stream_t *stream;
  component_t *component;
  
  if ( agent == NULL || stream_id < 1 || component_id < 1 )
     return;

  if (agent_find_component (agent, stream_id, component_id, &stream, &component)) {
    if (stream->gathering_started) {
      ICE_DEBUG("gatherting started, sid=%u", stream_id);
    } else {
      component->min_port = min_port;
      component->max_port = max_port;
    }
  }

  return;
}

void
ice_agent_remove_stream(agent_t *agent, uint32_t stream_id)
{
  //uint32_t stream_ids[] = { stream_id, 0 }; 
  stream_t *stream;

  if ( agent == NULL || stream_id < 1 )
     return;

  stream = agent_find_stream (agent, stream_id);
  if (!stream) {
    ICE_ERROR("stream not found, sid=%u",stream_id);
    return;
  }

  /* note: remove items with matching stream_ids from both lists */
  conn_check_prune_stream(agent, stream);
  discovery_prune_stream(agent, stream_id);
  refresh_prune_stream(agent, stream_id);

  /* Remove the stream and signal its removal. */
  //list_del(&stream->list);
  TAILQ_REMOVE(&agent->streams,stream,list);
  {
     struct list_head *i;
     stream_t *s = NULL;
     //list_for_each(i,&agent->streams.list) {
     //   stream_t *s = list_entry(i,stream_t,list);
     TAILQ_FOREACH(s,&agent->streams,list) {
        ICE_DEBUG("stream info, sid=%u",s->id);
     }
  }
  ice_stream_close(stream);

  if ( !TAILQ_EMPTY(&agent->streams) ) {
     /* FIXME: priv_remove_keepalive_timer */
     //priv_remove_keepalive_timer (agent);
  }


  /*
  if (!agent->streams)
    priv_remove_keepalive_timer (agent);
  agent_queue_signal (agent, signals[SIGNAL_STREAMS_REMOVED],
      g_memdup (stream_ids, sizeof(stream_ids)));
  stream_free(stream);*/

  return;
}

int
ice_agent_set_selected_remote_candidate( agent_t *agent, uint32_t stream_id, 
           uint32_t component_id, candidate_t *candidate)
{
  component_t *component;
  stream_t *stream;
  candidate_t *lcandidate = NULL;
  int ret = 0;
  candidate_t *local = NULL, *remote = NULL;
  uint64_t priority;

  if (agent == NULL || stream_id == 0 || component_id == 0 || candidate == NULL)
       return ret;

  /* step: check if the component exists*/
  if (agent_find_component(agent, stream_id, component_id, &stream, &component) != ICE_OK) {
    goto done;
  }

  /* step: stop connectivity checks (note: for the whole stream) */
  conn_check_prune_stream (agent, stream);

  /* Store previous selected pair */
  local = component->selected_pair.local;
  remote = component->selected_pair.remote;
  priority = component->selected_pair.priority;
  ICE_USE(local);
  ICE_USE(remote);
  ICE_USE(priority);

  /* step: set the selected pair */
  lcandidate = component_set_selected_remote_candidate(agent, component, candidate);
  if (!lcandidate)
    goto done;

  /* FIXME: reliable agent */
  /*if (agent->reliable && !nice_socket_is_reliable (lcandidate->sockptr) &&
      pseudo_tcp_socket_is_closed (component->tcp)) {
    nice_debug ("Agent %p: not setting selected remote candidate s%d:%d because"
        " pseudo tcp socket does not exist in reliable mode", agent,
        stream->id, component->id);
    // Revert back to previous selected pair //
    // FIXME: by doing this, we lose the keepalive tick //
    component->selected_pair.local = local;
    component->selected_pair.remote = remote;
    component->selected_pair.priority = priority;
    goto done;
  }*/

  /* step: change component state */
  ICE_ERROR("component state changed, sid=%u, cid=%u, state=%u",
            stream_id, component_id, ICE_COMPONENT_STATE_READY);

  agent_signal_component_state_change(agent, stream_id, component_id, ICE_COMPONENT_STATE_READY);
  agent_signal_new_selected_pair (agent, stream_id, component_id,
      lcandidate, candidate);

  ret = 1;

 done:
  return ret;
}

candidate_t*
ice_agent_get_remote_candidates(agent_t *agent, uint32_t stream_id, uint32_t component_id)
{
  component_t *component;
  struct list_head *item;
  candidate_t *ret = 0;

  if ( agent == NULL || stream_id < 1 || component_id < 1 ) {
     return NULL;
  }

  if (agent_find_component (agent, stream_id, component_id, NULL, &component) != ICE_OK) {    
     ICE_ERROR("component not found, sid=%u, cid=%u",stream_id,component_id);
     goto done;
  }    
  
  ret = candidate_new(ICE_CANDIDATE_TYPE_LAST);
  if ( ret == NULL ) {
     ICE_ERROR("can not create candidate, sid=%u, cid=%u",stream_id,component_id);
     goto done;
  }

  ICE_DEBUG("copy candidate list, sid=%u, cid=%u",stream_id,component_id);
  list_for_each(item,&component->remote_candidates.list) {
     candidate_t *c = list_entry(item,candidate_t,list);
     candidate_t *copy = candidate_copy(c); 
     if ( copy != NULL ) {
        list_add(&copy->list,&ret->list);
     } else {
        ICE_ERROR("can not copy candidate, sid=%u, cid=%u",stream_id,component_id);
     }
  }

done:
  return ret; 
}









