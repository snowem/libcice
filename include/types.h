/*
 * Copyright (c) 2016 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1 Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  2 Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *  3 Neither the name of the <organization> nor the 
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @(#)types.h
 */

#ifndef _ICE_TYPES_H_
#define _ICE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "log.h"

typedef struct _stream stream_t;
typedef struct _component component_t;
typedef struct _agent agent_t;
typedef struct _address address_t;
typedef struct _socket socket_t;
typedef struct _turnserver turnserver_t;
typedef struct _candidate candidate_t;
typedef struct _candidate_pair candidate_pair_t;
typedef struct _candidate_pair_keepalive candidate_pair_keepalive_t;
typedef struct _candidate_discovery candidate_discovery_t;
typedef struct _candidate_refresh candidate_refresh_t;
typedef struct _candidate_check_pair candidate_check_pair_t;
typedef struct _incoming_check incoming_check_t;
//typedef struct _stun_agent stun_agent_t;

typedef void (*agent_recv_func) (agent_t *agent, uint32_t stream_id, 
    uint32_t component_id, char *buf, uint32_t len, void  *user_data);

/* Constants for determining candidate priorities */
#define ICE_CANDIDATE_TYPE_PREF_HOST                 120
#define ICE_CANDIDATE_TYPE_PREF_PEER_REFLEXIVE       110
#define ICE_CANDIDATE_TYPE_PREF_NAT_ASSISTED         105
#define ICE_CANDIDATE_TYPE_PREF_SERVER_REFLEXIVE     100
#define ICE_CANDIDATE_TYPE_PREF_UDP_TUNNELED          75
#define ICE_CANDIDATE_TYPE_PREF_RELAYED               10

/* Priority preference constants for MS-ICE compatibility */
#define ICE_CANDIDATE_TRANSPORT_MS_PREF_UDP           15
#define ICE_CANDIDATE_TRANSPORT_MS_PREF_TCP            6
#define ICE_CANDIDATE_DIRECTION_MS_PREF_PASSIVE        2
#define ICE_CANDIDATE_DIRECTION_MS_PREF_ACTIVE         5

/* Max foundation size, see ICE ID-19  */
#define ICE_CANDIDATE_MAX_FOUNDATION                (32+1)
#define ICE_CANDIDATE_PAIR_MAX_FOUNDATION ICE_CANDIDATE_MAX_FOUNDATION*2

/* 
 * A hard limit for the number of remote candidates. This
 * limit is enforced to protect against malevolent remote
 * clients.
 */
#define ICE_AGENT_MAX_REMOTE_CANDIDATES    25
      


#define ICE_USE(p) (void)(p);
#define ICE_MALLOC(type_) (type_*)malloc(sizeof(type_))
#define ICE_FREE(p_) { if (p_!=NULL) free(p_); }
#define ICE_MEMZERO(p_,type_) memset(p_,0,sizeof(type_))

#define ICE_FALSE (0)
#define ICE_TRUE (1)

#define ICE_OK (0)
#define ICE_ERR (-1)
#define ICE_NULLPTR (-2)

#define ICE_HEXDUMP(p,len,type)\
{\
   char __buf__[4*1024];\
   int i, j, _i;\
   ICE_DEBUG("---- dump buffer (%s) ---- len=%d",type,len);\
   for (i = 0; i < (int)len; ) {\
      memset(__buf__, sizeof(__buf__), ' ');\
      sprintf(__buf__, "%5d: ", i); \
      _i = i;\
      for (j=0; j < 16 && i < (int)len; i++, j++)\
         sprintf(__buf__ +7+j*3, "%02x ", (uint8_t)((p)[i]));\
      i = _i;   \
      for (j=0; j < 16 && i < (int)len; i++, j++)\
         sprintf(__buf__ +7+j + 48, "%c",\
            isprint((p)[i]) ? (p)[i] : '.'); \
      ICE_DEBUG("%s: %s", type, __buf__);\
   }\
}

#define ICE_MAX(a, b)  (((a) > (b)) ? (a) : (b))
#define ICE_MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define ICE_ABS(a)	   (((a) < 0) ? -(a) : (a))
#define ICE_CLAMP(x, low, high)  (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))
#define ICE_OPEN(_f,_flags) open(_f,_flags)

/* An upper limit to size of STUN packets handled (based on Ethernet
 * MTU and estimated typical sizes of ICE STUN packet */
#define MAX_STUN_DATAGRAM_PAYLOAD    1300
#define MAX_BUF_SIZE 4*1024*1024


#ifdef __cplusplus
}
#endif

#endif //_TYPES_H_


