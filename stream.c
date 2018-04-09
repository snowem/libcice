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

#include "cice/stream.h"
#include "cice/types.h"

void 
stream_initialize_credentials (stream_t *stream/*, NiceRNG *rng*/)
{
  static const char *uname = "RObomhjs7tw7kmzf";
  static const char *pwd = "jVvUZXC05jO8vi2aqzb7Lerv";
  /* note: generate ufrag/pwd for the stream (see ICE 15.4.
   *       '"ice-ufrag" and "ice-pwd" Attributes', ID-19) */
  ICE_DEBUG("FIXME: generate ufrag/pwd for a stream");
  memcpy(stream->local_ufrag,uname,strlen(uname));
  memcpy(stream->local_password,pwd,strlen(pwd));
  //nice_rng_generate_bytes_print (rng, NICE_STREAM_DEF_UFRAG - 1, stream->local_ufrag);
  //nice_rng_generate_bytes_print (rng, NICE_STREAM_DEF_PWD - 1, stream->local_password);
}

stream_t*
stream_new (agent_t *agent, uint32_t n_components)
{
  stream_t *stream;
  uint32_t n;
  component_t *component;

  if (agent == 0 )
     return 0;

  stream = ICE_MALLOC(stream_t);
  if ( stream == 0 )
     return 0;
  ICE_MEMZERO(stream,stream_t);

  ICE_DEBUG("create new stream, stream=%p, n_components=%u", stream, n_components);

  TAILQ_INIT(&stream->components);
  INIT_LIST_HEAD(&stream->connchecks.list);

  for (n = 0; n < n_components; n++) {
    component = component_new (agent, stream, n + 1);
    TAILQ_INSERT_HEAD(&stream->components,component,list);
  }

  stream->n_components = n_components;
  stream->initial_binding_request_received = 0;
  stream->gathering_started = 0;

  return stream;
}

component_t *
stream_find_component_by_id (const stream_t *stream, uint32_t id)
{
   component_t *c;

   if (stream == NULL )
      return NULL;

   TAILQ_FOREACH(c,&stream->components,list) {
      if ( c->id == id )
         return c;
   }

  return NULL;
}

/*
 * Returns true if all components of the stream are either
 * 'CONNECTED' or 'READY' (connected plus nominated).
 */
int
stream_all_components_ready(const stream_t *stream)
{
  component_t *component = NULL;

  TAILQ_FOREACH(component,&stream->components,list) {
    if ( component &&
	     !(component->state == ICE_COMPONENT_STATE_CONNECTED ||
	      component->state == ICE_COMPONENT_STATE_READY))
      return ICE_ERR;
  }

  return ICE_OK;
}


void
ice_stream_close(stream_t *s) {
  component_t *c = NULL;

  while (!TAILQ_EMPTY(&s->components)) {
    c = TAILQ_FIRST(&s->components);
    TAILQ_REMOVE(&s->components, c, list);
    ice_component_close(c);
  }


  return;
}



