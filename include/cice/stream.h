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

#ifndef _ICE_STREAM_H_
#define _ICE_STREAM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "component.h"
#include "conncheck.h"
#include "list.h"
#include "types.h"


/* Maximum and default sizes for ICE attributes, 
 * last updated from ICE ID-19 
 * (the below sizes include the terminating NULL): */

#define ICE_STREAM_MAX_UFRAG   256 + 1  /* ufrag + NULL */
#define ICE_STREAM_MAX_UNAME   256 * 2 + 1 + 1 /* 2*ufrag + colon + NULL */
#define ICE_STREAM_MAX_PWD     256 + 1  /* pwd + NULL */
#define ICE_STREAM_DEF_UFRAG   4 + 1    /* ufrag + NULL */
#define ICE_STREAM_DEF_PWD     22 + 1   /* pwd + NULL */

struct _stream
{
  struct list_head list;

  uint32_t id;
  uint32_t n_components;
  uint32_t tos;
  char *name;
  char local_ufrag[ICE_STREAM_MAX_UFRAG];
  char local_password[ICE_STREAM_MAX_PWD];
  char remote_ufrag[ICE_STREAM_MAX_UFRAG];
  char remote_password[ICE_STREAM_MAX_PWD];

  component_t            components;  /* list of 'Component' structs */
  candidate_check_pair_t connchecks;  /* list of CandidateCheckPair items */

  /* boolean properties */
  uint8_t initial_binding_request_received;
  uint8_t gathering;
  uint8_t gathering_started;
  
};


stream_t*
stream_new(agent_t *agent, uint32_t n_components);

component_t *
stream_find_component_by_id(const stream_t *stream, uint32_t id);

void 
stream_initialize_credentials(stream_t *stream/*, NiceRNG *rng*/);

int
stream_all_components_ready(const stream_t *stream);

void
ice_stream_close(stream_t *s);

#ifdef __cplusplus
}
#endif

#endif  //_STREAM_H_



