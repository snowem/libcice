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

#include "stun.h"
#include "stun/constants.h"
#include "stun/stunmessage.h"
#include "stun/utils.h"

size_t
is_stun_message(uint8_t *buffer, int len, int has_padding) {
   int mlen;

   //ICE_DEBUG("STUN info, has_padding=%u",has_padding);

   if (len < 1  || buffer == NULL) {
      ICE_DEBUG("STUN error: No data!");
      return STUN_MESSAGE_BUFFER_INVALID;
   }

   if (buffer[0] >> 6) {
      //ICE_ERROR("STUN error: RTP or other non-protocol packet!");
      return STUN_MESSAGE_BUFFER_INVALID; // RTP or other non-STUN packet
   }

   if (len < STUN_MESSAGE_LENGTH_POS + STUN_MESSAGE_LENGTH_LEN) {
      //ICE_DEBUG("STUN error: Incomplete STUN message header!");
      return STUN_MESSAGE_BUFFER_INCOMPLETE;
   }

   mlen = stun_getw((uint8_t*)buffer + STUN_MESSAGE_LENGTH_POS);
   mlen += STUN_MESSAGE_HEADER_LENGTH;

   if (has_padding && stun_padding (mlen)) {
      //ICE_DEBUG("STUN error: Invalid message length: %u!", (unsigned)mlen);
      return STUN_MESSAGE_BUFFER_INVALID; // wrong padding
   }

   if (len < mlen) {
      ICE_ERROR("STUN error: Incomplete message: %u of %u bytes!",
        (unsigned) len, (unsigned) mlen);
      return STUN_MESSAGE_BUFFER_INCOMPLETE; // partial message
   }

   return mlen;
}

int
is_validated_stun_message(uint8_t *msg, int length, int has_padding) {
   ssize_t fast_retval;
   size_t mlen;
   size_t len;
 
   //FIXME: pre-check is really needed? 
   fast_retval = is_stun_message(msg,length,has_padding);
  
   if ( fast_retval <= 0 ) 
      return fast_retval;

   mlen = fast_retval;    

   /* Skip past the header (validated above). */
   msg += 20;
   len = mlen - 20;

   /* from then on, we know we have the entire packet in buffer */
   while (len > 0)
   {
      size_t alen;

      if (len < 4)
      {
         ICE_DEBUG("STUN error: Incomplete STUN attribute header of length "
          "%u bytes!", (unsigned)len);
         return STUN_MESSAGE_BUFFER_INVALID;
      }

      alen = stun_getw (msg + STUN_ATTRIBUTE_TYPE_LEN);
      if (has_padding)
         alen = stun_align (alen);

      /* thanks to padding check, if (end > msg) then there is not only one
       * but at least 4 bytes left */
      len -= 4;

      if (len < alen)
      {
         ICE_DEBUG("STUN error: %u instead of %u bytes for attribute!",
             (unsigned)len, (unsigned)alen);
         return STUN_MESSAGE_BUFFER_INVALID; // no room for attribute value + padding
      }

      len -= alen;
      msg += 4 + alen;
   }
   ICE_DEBUG("stun msg, mlen=%lu",mlen);
   return mlen;
}







