/*
 * Copyright (c) 2014 Stephen B. Vinoski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"
#include "erl_nif.h"

#define HMAC_STRING 0x1
#define HMAC_UPPER  0x2

static const char UPPER[] = "0123456789ABCDEF";
static const char LOWER[] = "0123456789abcdef";

static ERL_NIF_TERM
hexlify_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary bin, ret;
    unsigned int flags = 0;
    unsigned i, j;
    const char* digits;

    if (argc != 2 ||
        !enif_inspect_binary(env, argv[0], &bin) ||
        !enif_get_uint(env, argv[1], &flags)) {
        return enif_make_badarg(env);
    }
    digits = (flags & HMAC_UPPER) ? UPPER : LOWER;
    enif_alloc_binary(bin.size*2, &ret);
    for (i = 0, j = 0; i < bin.size; ++i) {
        unsigned char c = bin.data[i];
        ret.data[j++] = digits[(c & 0xF0) >> 4];
        ret.data[j++] = digits[(c & 0x0F)];
    }
    if (flags & HMAC_STRING) {
        const char* data = (char*)ret.data;
        ERL_NIF_TERM s = enif_make_string_len(env, data, ret.size, ERL_NIF_LATIN1);
        enif_release_binary(&ret);
        return s;
    } else {
        return enif_make_binary(env, &ret);
    }
}

static ErlNifFunc funcs[] = {
    {"hexlify_nif", 2, hexlify_nif},
};

ERL_NIF_INIT(hmac, funcs, NULL, NULL, NULL, NULL)
