/*
 * Copyright (c) 2024, Renaud Allard
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef QUIC_LISTENER_H
#define QUIC_LISTENER_H

struct Listener;
struct ev_loop;

struct QuicListenerStats {
    unsigned long long client_datagrams_received;
    unsigned long long client_datagrams_forwarded;
    unsigned long long backend_datagrams_received;
    unsigned long long backend_datagrams_forwarded;
    unsigned long long sessions_started;
    unsigned long long sessions_destroyed;
    unsigned long long sessions_resumed;
    unsigned long long parse_failures;
    unsigned long long lookup_failures;
    unsigned long long fallback_invocations;
    unsigned long long backend_init_failures;
    unsigned long long client_send_errors;
    unsigned long long backend_send_errors;
    unsigned long long backend_receive_errors;
};

int accept_quic_client(struct Listener *, struct ev_loop *);
int quic_listener_attach(struct Listener *, struct ev_loop *);
void quic_listener_detach(struct Listener *, struct ev_loop *);
const struct QuicListenerStats *quic_listener_get_stats(const struct Listener *);
void quic_listener_reset_stats(struct Listener *);


#endif
