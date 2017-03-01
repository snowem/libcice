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


#include "component.h"
#include "agent.h"

void
incoming_check_free(incoming_check_t *icheck)
{
   /* FIXME: incoming_check_free */
   /*free (icheck->username);
   g_slice_free (IncomingCheck, icheck);*/
}


component_t *
component_new (agent_t *agent, stream_t *stream, uint32_t id)
{
  component_t *component;

  ICE_DEBUG("created component, cid=%u", id);
  component = ICE_MALLOC(component_t);
  component->id = id;
  component->state = ICE_COMPONENT_STATE_DISCONNECTED;
  component->restart_candidate = 0;
  component->tcp = 0;
  component->agent = agent;
  component->stream = stream;
  INIT_LIST_HEAD(&component->local_candidates.list);
  INIT_LIST_HEAD(&component->remote_candidates.list);
  INIT_LIST_HEAD(&component->incoming_checks.list);

  ice_agent_init_stun_agent(agent, &component->stun_agent);
  return component;
}

void
component_set_io_callback (component_t *component, 
             agent_recv_func cb, void *user_data) {
  
  if ( component == 0 )
     return;

  ICE_ERROR("FIXME: set io callback");
  component->io_callback = cb;
  component->io_data = user_data;
 
  return;
}

void
component_attach_socket (component_t *component, socket_t *nicesock)
{
  if (component == NULL || nicesock == NULL)
     return;

  /* FIXME Create and attach a source */
  //nicesock->component = component;
  
  return;
}

candidate_t *
component_find_remote_candidate(const component_t *component, 
  const address_t *addr, IceCandidateTransport transport)
{
   struct list_head *pos;

   list_for_each(pos,&component->remote_candidates.list) {
      candidate_t *candidate = list_entry(pos,candidate_t,list);
      if ( address_equal(&candidate->addr,addr) &&
           candidate->transport == transport ) {
         return candidate;
      }
   }
 
  return NULL;
}

static void 
component_clear_selected_pair (component_t *component)
{
   /* FIXME: clear timeout for selected pair */
  /*if (component->selected_pair.keepalive.tick_source != NULL) {
    g_source_destroy (component->selected_pair.keepalive.tick_source);
    g_source_unref (component->selected_pair.keepalive.tick_source);
    component->selected_pair.keepalive.tick_source = NULL;
  }*/
  memset(&component->selected_pair, 0, sizeof(candidate_pair_t));
}
/*
 * Changes the selected pair for the component to 'pair'. Does not
 * emit the "selected-pair-changed" signal.
 */ 
void 
component_update_selected_pair (component_t *component, const candidate_pair_t *pair)
{
  if ( component == NULL || pair == NULL )
     return;

  ICE_DEBUG("setting SELECTED PAIR for component %u: %s:%s (prio:%lu)", component->id, pair->local->foundation,
      pair->remote->foundation, pair->priority);

  /* FIXME: clean socket resources */
  /*if (component->selected_pair.local &&
      component->selected_pair.local == component->turn_candidate) {
    refresh_prune_candidate(component->agent, component->turn_candidate);
    discovery_prune_socket(component->agent, component->turn_candidate->sockptr);
    conn_check_prune_socket (component->agent, component->stream, component,
        component->turn_candidate->sockptr);
    component_detach_socket (component, component->turn_candidate->sockptr);
    candidate_free (component->turn_candidate);
    component->turn_candidate = NULL;
  }*/

  component_clear_selected_pair(component);

  component->selected_pair.local = pair->local;
  component->selected_pair.remote = pair->remote;
  component->selected_pair.priority = pair->priority;

}

/*
 * Finds a candidate pair that has matching foundation ids.
 *
 * @return TRUE if pair found, pointer to pair stored at 'pair'
 */
int
component_find_pair(component_t *cmp, agent_t *agent, const char *lfoundation, 
   const char *rfoundation, candidate_pair_t *pair)
{

  struct list_head *i;
  candidate_pair_t result = { 0, };

  ICE_DEBUG("find component pair, lfoundation=%s,rfoundation=%s",
        lfoundation,rfoundation);

  list_for_each(i,&cmp->local_candidates.list) {
    candidate_t *candidate = list_entry(i,candidate_t,list);
    if (strncmp(candidate->foundation, lfoundation, ICE_CANDIDATE_MAX_FOUNDATION) == 0) {
      result.local = candidate;
      break;
    }
  }

  list_for_each(i,&cmp->remote_candidates.list) {
    candidate_t *candidate = list_entry(i,candidate_t,list);
    if (strncmp (candidate->foundation, rfoundation, ICE_CANDIDATE_MAX_FOUNDATION) == 0) {
      result.remote = candidate;
      break;
    }
  }

  if (result.local && result.remote) {
    result.priority = agent_candidate_pair_priority(agent, result.local, result.remote);
    if (pair)
      *pair = result;
    return ICE_OK;
  }

  return ICE_ERR;

}

candidate_t *
component_set_selected_remote_candidate(agent_t *agent, 
       component_t *component, candidate_t *candidate)
{
  candidate_t *local = NULL;
  candidate_t *remote = NULL;
  uint64_t priority = 0;
  struct list_head *item = NULL;

  if (candidate == NULL)
     return NULL;

  //for (item = component->local_candidates; item; item = g_slist_next (item)) {
  list_for_each(item,&component->local_candidates.list) {
    candidate_t *tmp = list_entry(item,candidate_t,list);
    uint64_t tmp_prio = 0;

    if (tmp->transport != candidate->transport ||
	tmp->addr.s.addr.sa_family != candidate->addr.s.addr.sa_family ||
        tmp->type != ICE_CANDIDATE_TYPE_HOST)
      continue;

    tmp_prio = agent_candidate_pair_priority (agent, tmp, candidate);

    if (tmp_prio > priority) {
      priority = tmp_prio;
      local = tmp;
    }
  }

  if (local == NULL)
    return NULL;

  remote = component_find_remote_candidate(component, &candidate->addr,
      candidate->transport);

  ICE_DEBUG("got remote, remote=%p",remote);
  if (!remote) {
    remote = candidate_copy(candidate);
    //component->remote_candidates = g_slist_append (component->remote_candidates, remote);
    list_add(&remote->list,&component->remote_candidates.list);
    agent_signal_new_remote_candidate(agent, remote);
  }

  component_clear_selected_pair (component);

  component->selected_pair.local = local;
  component->selected_pair.remote = remote;
  component->selected_pair.priority = priority;

  return local;
}



