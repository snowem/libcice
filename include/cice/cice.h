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
 * @(#)cice.h
 */

#ifndef _CICE_CICE_H_
#define _CICE_CICE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "cice/address.h"
#include "cice/agent.h"
#include "cice/base64.h"
#include "cice/candidate.h"
#include "cice/common.h"
#include "cice/component.h"
#include "cice/conncheck.h"
#include "cice/discovery.h"
#include "cice/event.h"
#include "cice/interfaces.h"
#include "cice/list.h"
#include "cice/list_sort.h"
#include "cice/log.h"
#include "cice/network.h"
#include "cice/socket.h"
#include "cice/stream.h"
#include "cice/stun/constants.h"
#include "cice/stun/debug.h"
#include "cice/stun/md5.h"
#include "cice/stun/rand.h"
#include "cice/stun/sha1.h"
#include "cice/stun/stun5389.h"
#include "cice/stun/stunagent.h"
#include "cice/stun/stuncrc32.h"
#include "cice/stun/stunhmac.h"
#include "cice/stun/stunmessage.h"
#include "cice/stun/utils.h"
#include "cice/stun/usages/bind.h"
#include "cice/stun/usages/ice.h"
#include "cice/stun/usages/timer.h"
#include "cice/stun/usages/turn.h"
#include "cice/stunagent.h"
#include "cice/stun.h"
#include "cice/types.h"
#include "cice/utils.h"

#endif //_CICE_CICE_H_


