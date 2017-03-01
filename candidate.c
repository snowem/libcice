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

#include "candidate.h"

candidate_t *
candidate_new(IceCandidateType type)
{
  candidate_t *candidate;

  candidate = ICE_MALLOC(candidate_t);
  if (candidate == NULL)
     return NULL;
  ICE_MEMZERO(candidate,candidate_t);
  INIT_LIST_HEAD(&candidate->list);
  candidate->type = type;
  return candidate;
}

uint32_t
candidate_jingle_priority (candidate_t *candidate)
{
   if (candidate == NULL )
      return 0;

   switch (candidate->type)
     {
     case ICE_CANDIDATE_TYPE_HOST:             return 1000;
     case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return 900;
     case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:   return 900;
     case ICE_CANDIDATE_TYPE_RELAYED:          return 500;
     default:                                   return 0;
     }
   return 0;
}

uint32_t
candidate_msn_priority (candidate_t *candidate)
{
   if (candidate == NULL )
      return 0;

   switch (candidate->type)
    {
    case ICE_CANDIDATE_TYPE_HOST:             return 830;
    case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE: return 550;
    case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:   return 550;
    case ICE_CANDIDATE_TYPE_RELAYED:          return 450;
    default:                                   return 0;
    }

   return 0;
}

static uint8_t
candidate_ice_type_preference (const candidate_t *candidate,
    int reliable, int nat_assisted)
{
  uint8_t type_preference;

  if (candidate == NULL )
     return 0;

  switch (candidate->type)
    {
    case ICE_CANDIDATE_TYPE_HOST:
      type_preference = ICE_CANDIDATE_TYPE_PREF_HOST;
      break;
    case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
      type_preference = ICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE;
      break;
    case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
      if (nat_assisted)
        type_preference = ICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED;
      else
        type_preference = ICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE;
      break;
    case ICE_CANDIDATE_TYPE_RELAYED:
      type_preference = ICE_CANDIDATE_TYPE_PREF_RELAYED;
      break;
    default:
      type_preference = 0;
      break;
    }

  if ((reliable && candidate->transport == ICE_CANDIDATE_TRANSPORT_UDP) ||
      (!reliable && candidate->transport != ICE_CANDIDATE_TRANSPORT_UDP)) {
    type_preference = type_preference / 2;
  }

  return type_preference;
}

static uint32_t
candidate_ms_ice_local_preference_full (uint32_t transport_preference,
    uint32_t direction_preference, uint32_t other_preference)
{
  return 0x1000 * transport_preference +
      0x200 * direction_preference +
      0x1 * other_preference;
}


static uint32_t
candidate_ms_ice_local_preference (const candidate_t *candidate)
{
  uint8_t transport_preference = 0;
  uint8_t direction_preference = 0;

  switch (candidate->transport)
    {
    case ICE_CANDIDATE_TRANSPORT_TCP_SO:
    case ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
      transport_preference = ICE_CANDIDATE_TRANSPORT_MS_PREF_TCP;
      direction_preference = ICE_CANDIDATE_DIRECTION_MS_PREF_ACTIVE;
      break;
    case ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
      transport_preference = ICE_CANDIDATE_TRANSPORT_MS_PREF_TCP;
      direction_preference = ICE_CANDIDATE_DIRECTION_MS_PREF_PASSIVE;
      break;
    case ICE_CANDIDATE_TRANSPORT_UDP:
    default:
      transport_preference = ICE_CANDIDATE_TRANSPORT_MS_PREF_UDP;
      break;
    }

  return candidate_ms_ice_local_preference_full(transport_preference,
      direction_preference, 0);
}

uint32_t
candidate_ice_priority_full (
  // must be ∈ (0, 126) (max 2^7 - 2)
  uint32_t type_preference,
  // must be ∈ (0, 65535) (max 2^16 - 1)
  uint32_t local_preference,
  // must be ∈ (0, 255) (max 2 ^ 8 - 1)
  uint32_t component_id)
{
  return (
      0x1000000 * type_preference +
      0x100 * local_preference +
      (0x100 - component_id));
}


uint32_t
candidate_ms_ice_priority (const candidate_t *candidate,
    int reliable, int nat_assisted)
{
  uint8_t type_preference;
  uint16_t local_preference;

  type_preference = candidate_ice_type_preference (candidate, reliable,
      nat_assisted);
  local_preference = candidate_ms_ice_local_preference (candidate);

  return candidate_ice_priority_full (type_preference, local_preference,
      candidate->component_id);
}

static uint32_t
candidate_ice_local_preference_full (uint32_t direction_preference,
    uint32_t other_preference)
{
  return (0x2000 * direction_preference +
      other_preference);
}

static uint16_t
candidate_ice_local_preference (const candidate_t *candidate)
{
  uint32_t direction_preference;

  switch (candidate->transport)
    {
      case ICE_CANDIDATE_TRANSPORT_TCP_ACTIVE:
        if (candidate->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
            candidate->type == ICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED)
          direction_preference = 4;
        else
          direction_preference = 6;
        break;
      case ICE_CANDIDATE_TRANSPORT_TCP_PASSIVE:
        if (candidate->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
            candidate->type == ICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED)
          direction_preference = 2;
        else
          direction_preference = 4;
        break;
      case ICE_CANDIDATE_TRANSPORT_TCP_SO:
        if (candidate->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE ||
            candidate->type == ICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED)
          direction_preference = 6;
        else
          direction_preference = 2;
        break;
      case ICE_CANDIDATE_TRANSPORT_UDP:
      default:
        return 1;
        break;
    }

  return candidate_ice_local_preference_full (direction_preference, 1);
}


uint32_t
candidate_ice_priority (const candidate_t *candidate,
    int reliable, int nat_assisted)
{
  uint8_t type_preference;
  uint16_t local_preference;

  type_preference = candidate_ice_type_preference (candidate, reliable,
      nat_assisted);
  local_preference = candidate_ice_local_preference (candidate);

  return candidate_ice_priority_full (type_preference, local_preference,
      candidate->component_id);
}

void
candidate_free(candidate_t *candidate)
{
  if ( candidate == NULL )
     return;

  if (candidate->username)
    ICE_FREE(candidate->username);

  if (candidate->password)
    ICE_FREE(candidate->password);

  ICE_DEBUG("FIXME: free turn pointer");
  //if (candidate->turn)
  //  turn_server_unref (candidate->turn);

  ICE_DEBUG("FIXME: free list of candidate");
  ICE_FREE(candidate);
}

/*
 * Calculates the pair priority as specified in ICE
 * sect 5.7.2. "Computing Pair Priority and Ordering Pairs" (ID-19).
 */
uint64_t
candidate_pair_priority(uint32_t o_prio, uint32_t a_prio)
{
  uint32_t max = o_prio > a_prio ? o_prio : a_prio;
  uint32_t min = o_prio < a_prio ? o_prio : a_prio;
  /* These two constants are here explictly to make some version of GCC happy */
  const uint64_t one = 1;
  const uint64_t thirtytwo = 32;

  return (one << thirtytwo) * min + 2 * max + (o_prio > a_prio ? 1 : 0);
}

candidate_t*
candidate_copy(const candidate_t *candidate)
{
  candidate_t *copy;

  if ( candidate == NULL )
     return NULL;

  copy = candidate_new(candidate->type);
  if ( copy == NULL )
     return NULL;
  copy->transport = candidate->transport;
  copy->addr = candidate->addr;
  copy->base_addr = candidate->base_addr;
  copy->priority = candidate->priority;
  copy->stream_id = candidate->stream_id;
  copy->component_id = candidate->component_id;
  memcpy(copy->foundation,candidate->foundation,ICE_CANDIDATE_MAX_FOUNDATION);
  if ( candidate->username )
     copy->username = strdup (candidate->username);
  if ( candidate->password )
     copy->password = strdup (candidate->password);
  copy->turn = NULL;

  return copy;
}

void
print_candidate(candidate_t *c) 
{
   char temp[INET6_ADDRSTRLEN] = {0};
   if ( c == NULL )
      return;

   address_to_string(&c->addr,temp);

   ICE_DEBUG("candidate info, addr=%s, port=%u foundation=%s, type=%u",
         temp,address_get_port((const address_t*)&c->addr),c->foundation,c->type);

   return;
}

