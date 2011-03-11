/*
 * Copyright (c) 2009-2011 Stephen B. Vinoski
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
#if HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <string.h>
#include "erl_nif.h"


#ifndef WORDS_BIGENDIAN
#define BYTESWAP32(x)                           \
    ((((uint32_t)(x) & 0x000000FF) << 24) |     \
     (((uint32_t)(x) & 0x0000FF00) << 8)  |     \
     (((uint32_t)(x) >> 8) & 0x0000FF00)  |     \
     (((uint32_t)(x) >> 24) & 0x000000FF))

#define	BYTESWAP64(x)                                          \
    (((uint64_t)(x) << 56) |                                   \
     (((uint64_t)(x) << 40) & 0X00FF000000000000ULL) |         \
     (((uint64_t)(x) << 24) & 0X0000FF0000000000ULL) |         \
     (((uint64_t)(x) << 8)  & 0X000000FF00000000ULL) |         \
     (((uint64_t)(x) >> 8)  & 0X00000000FF000000ULL) |         \
     (((uint64_t)(x) >> 24) & 0X0000000000FF0000ULL) |         \
     (((uint64_t)(x) >> 40) & 0X000000000000FF00ULL) |         \
     ((uint64_t)(x)  >> 56))
#endif

static uint32_t H224[] = {
    0xC1059ED8,
    0x367CD507,
    0x3070DD17,
    0xF70E5939,
    0xFFC00B31,
    0x68581511,
    0x64F98FA7,
    0xBEFA4FA4,
};

static uint32_t H256[] = {
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
};

static uint64_t H384[] = {
    0xCBBB9D5DC1059ED8ULL,
    0x629A292A367CD507ULL,
    0x9159015A3070DD17ULL,
    0x152FECD8F70E5939ULL,
    0x67332667FFC00B31ULL,
    0x8EB44A8768581511ULL,
    0xDB0C2E0D64F98FA7ULL,
    0x47B5481DBEFA4FA4ULL,
};

static uint64_t H512[] = {
    0x6A09E667F3BCC908ULL,
    0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL,
    0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL,
    0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL,
    0x5BE0CD19137E2179ULL,
};

static uint32_t K256[] = {
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
};

static uint64_t K512[] = {
    0x428A2F98D728AE22ULL,
    0x7137449123EF65CDULL,
    0xB5C0FBCFEC4D3B2FULL,
    0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL,
    0x59F111F1B605D019ULL,
    0x923F82A4AF194F9BULL,
    0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL,
    0x12835B0145706FBEULL,
    0x243185BE4EE4B28CULL,
    0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL,
    0x80DEB1FE3B1696B1ULL,
    0x9BDC06A725C71235ULL,
    0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL,
    0xEFBE4786384F25E3ULL,
    0x0FC19DC68B8CD5B5ULL,
    0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL,
    0x4A7484AA6EA6E483ULL,
    0x5CB0A9DCBD41FBD4ULL,
    0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL,
    0xA831C66D2DB43210ULL,
    0xB00327C898FB213FULL,
    0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL,
    0xD5A79147930AA725ULL,
    0x06CA6351E003826FULL,
    0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL,
    0x2E1B21385C26C926ULL,
    0x4D2C6DFC5AC42AEDULL,
    0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL,
    0x766A0ABB3C77B2A8ULL,
    0x81C2C92E47EDAEE6ULL,
    0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL,
    0xA81A664BBC423001ULL,
    0xC24B8B70D0F89791ULL,
    0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL,
    0xD69906245565A910ULL,
    0xF40E35855771202AULL,
    0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL,
    0x1E376C085141AB53ULL,
    0x2748774CDF8EEB99ULL,
    0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL,
    0x4ED8AA4AE3418ACBULL,
    0x5B9CCA4F7763E373ULL,
    0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL,
    0x78A5636F43172F60ULL,
    0x84C87814A1F0AB72ULL,
    0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL,
    0xA4506CEBDE82BDE9ULL,
    0xBEF9A3F7B2C67915ULL,
    0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL,
    0xD186B8C721C0C207ULL,
    0xEADA7DD6CDE0EB1EULL,
    0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL,
    0x0A637DC5A2C898A6ULL,
    0x113F9804BEF90DAEULL,
    0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL,
    0x32CAAB7B40C72493ULL,
    0x3C9EBE0A15C9BEBCULL,
    0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL,
    0x597F299CFC657E2AULL,
    0x5FCB6FAB3AD6FAECULL,
    0x6C44198C4A475817ULL,
};

#define PADDED_SIZE_2XX       512
#define PADDED_SIZE_2XX_BYTES PADDED_SIZE_2XX/8
#define CONGRUENCE_2XX        448
#define PADDED_SIZE_5XX       1024
#define PADDED_SIZE_5XX_BYTES PADDED_SIZE_5XX/8
#define CONGRUENCE_5XX        896

typedef struct {
    uint64_t bitlen;
    unsigned char bytes[2*PADDED_SIZE_5XX_BYTES];
    ErlNifBinary digest;
    size_t count;
    size_t size;
} Context;

typedef union {
    Context* c;
    void*    v;
} ContextUnion;

typedef void (*ChunkHandler)(Context* ctx, unsigned char* chunk);

typedef ERL_NIF_TERM (*TermArgcArgvFun)(
    ErlNifEnv* env,
    int argc,
    const ERL_NIF_TERM argv[]
);
typedef int (*BoolArgcArgvFun)(
    ErlNifEnv* env,
    int argc,
    const ERL_NIF_TERM argv[]
);

static void
pad(unsigned char* bin, uint64_t binsize, Context* ctx)
{
    unsigned char* p;
    uint64_t congruence = ctx->size == PADDED_SIZE_2XX_BYTES ?
        CONGRUENCE_2XX : CONGRUENCE_5XX;
    uint64_t lenbits = ctx->bitlen;
    uint64_t pad;

    while (lenbits + 1 > congruence) {
        congruence += ctx->size*8;
    }
    pad = (congruence - (lenbits + 1)) / 8;
    if (ctx->size == PADDED_SIZE_5XX_BYTES) {
        pad += 8;
    }
    if (bin != NULL && binsize > 0) {
        memcpy(ctx->bytes + ctx->count, bin, binsize);
        ctx->count += binsize;
    }
    p = ctx->bytes + ctx->count;
    *p++ = 0x80;
    memset(p, 0, pad);
#ifndef WORDS_BIGENDIAN
    *(uint64_t*)(p + pad) = BYTESWAP64(lenbits);
#else
    *(uint64_t*)(p + pad) = lenbits;
#endif
    ctx->count += 1 + pad + sizeof lenbits;
}

static void
context_init(Context* ctx, void* hashes, size_t hsize, size_t padsize)
{
    enif_alloc_binary(hsize, &ctx->digest);
    memcpy(ctx->digest.data, hashes, hsize);
    ctx->bitlen = 0;
    ctx->count = 0;
    ctx->size = padsize/8;
}

static ERL_NIF_TERM
context_fini(ErlNifEnv* env, Context* ctx, size_t dsize, ChunkHandler handler)
{
    ERL_NIF_TERM result;
    ctx->bitlen += ctx->count*8;
    pad(0, 0, ctx);
    handler(ctx, ctx->bytes);
    if (ctx->count > ctx->size) {
        handler(ctx, ctx->bytes + ctx->size);
    }
#ifndef WORDS_BIGENDIAN
    {
        int i;
        if (ctx->size == PADDED_SIZE_2XX_BYTES) {
            uint32_t* hash = (uint32_t*)ctx->digest.data;
            for (i = 0; i < ctx->digest.size/sizeof(*hash); ++i) {
                hash[i] = BYTESWAP32(hash[i]);
            }
        } else {
            uint64_t* hash = (uint64_t*)ctx->digest.data;
            for (i = 0; i < ctx->digest.size/sizeof(*hash); ++i) {
                hash[i] = BYTESWAP64(hash[i]);
            }
        }
    }
#endif
    if (ctx->digest.size != dsize) {
        enif_realloc_binary(&ctx->digest, dsize);
    }
    result = enif_make_binary(env, &ctx->digest);
    ctx->digest.size = 0;
    return result;
}

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & z))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTR(v, rotate, width) (((v) >> (rotate)) | ((v) << ((width)-(rotate))))
#define ROTR32(v, rotate) ROTR(v, rotate, 32)
#define ROTR64(v, rotate) ROTR(v, rotate, 64)
#define SHIFTR(v, shift) ((v) >> (shift))

#define BIG_SIGMA256_0(x) (ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define BIG_SIGMA256_1(x) (ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SM_SIGMA256_0(x)  (ROTR32(x,7) ^ ROTR32(x,18) ^ SHIFTR(x,3))
#define SM_SIGMA256_1(x)  (ROTR32(x,17) ^ ROTR32(x,19) ^ SHIFTR(x,10))

#define BIG_SIGMA512_0(x) (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define BIG_SIGMA512_1(x) (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))
#define SM_SIGMA512_0(x)  (ROTR64(x,1) ^ ROTR64(x,8) ^ SHIFTR(x,7))
#define SM_SIGMA512_1(x)  (ROTR64(x,19) ^ ROTR64(x,61) ^ SHIFTR(x,6))

#define DIGEST_SIZE_224 28
#define DIGEST_SIZE_256 32
#define DIGEST_SIZE_384 48
#define DIGEST_SIZE_512 64

static void
sha_update_chunks(Context* ctx, ErlNifBinary* data, ChunkHandler handler)
{
    size_t chunk, chunk_total, datasize, extra;
    unsigned char* p = data->data;
    datasize = data->size;
    if (ctx->count != 0) {
        extra = ctx->size - ctx->count;
        if (extra > datasize) {
            extra = datasize;
        }
        memcpy(ctx->bytes + ctx->count, p, extra);
        ctx->count += extra;
        if (ctx->count == ctx->size) {
            handler(ctx, ctx->bytes);
            ctx->bitlen += ctx->size*8;
            ctx->count = 0;
        }
        p += extra;
        datasize -= extra;
    }
    chunk_total = datasize/ctx->size;
    for (chunk = 0; chunk < chunk_total; ++chunk) {
        handler(ctx, p);
        ctx->bitlen += ctx->size*8;
        p += ctx->size;
        datasize -= ctx->size;
    }
    extra = datasize % ctx->size;
    if (extra != 0) {
        memcpy(ctx->bytes, p, extra);
        ctx->count = extra;
    }
}

static void
sha2xx_chunk(Context* ctx, unsigned char* chunk)
{
    uint32_t* hash = (uint32_t*)ctx->digest.data;
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t words[64];
    int i;
#ifndef WORDS_BIGENDIAN
    {
        uint32_t* from = (uint32_t*)chunk;
        for (i = 0; i < 16; ++i) {
            words[i] = BYTESWAP32(from[i]);
        }
    }
#else
    memcpy(words, chunk, 16*sizeof(*words));
#endif
    for (i = 16; i < sizeof(words)/sizeof(*words); ++i) {
        uint32_t w15 = words[i-15], w2 = words[i-2];
        uint32_t s0 = SM_SIGMA256_0(w15), s1 = SM_SIGMA256_1(w2);
        uint32_t w7 = words[i-7], w16 = words[i-16];
        words[i] = s1 + w7 + s0 + w16;
    }
    a = hash[0]; b = hash[1]; c = hash[2]; d = hash[3];
    e = hash[4]; f = hash[5]; g = hash[6]; h = hash[7];
    for (i = 0; i < sizeof(words)/sizeof(*words); ++i) {
        uint32_t t1, t2;
        t1 = h + BIG_SIGMA256_1(e) + CH(e,f,g) + K256[i] + words[i];
        t2 = BIG_SIGMA256_0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
    hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
}

static ERL_NIF_TERM
sha(
    ErlNifEnv* env,
    int argc,
    const ERL_NIF_TERM argv[],
    TermArgcArgvFun hd_init,
    BoolArgcArgvFun hd_update,
    TermArgcArgvFun hd_final
)
{
    ERL_NIF_TERM ctx = hd_init(env, argc, argv);
    ERL_NIF_TERM args[2] = {ctx, argv[0]};
    ERL_NIF_TERM nargs[1];
    if (!hd_update(env, 2, args)) {
        return enif_make_badarg(env);
    }
    nargs[0] = ctx;
    return hd_final(env, 1, nargs);
}

static ERL_NIF_TERM
hd224_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM result;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    Context* ctx = (Context*)enif_alloc_resource(ctx_type, sizeof(Context));
    context_init(ctx, H224, sizeof H224, PADDED_SIZE_2XX);
    result = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return result;
}

static int
hd2xx_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary data;
    ContextUnion ctxu;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    if (!enif_get_resource(env, argv[0], ctx_type, &ctxu.v)) {
        return 0;
    }
    if (!enif_inspect_iolist_as_binary(env, argv[1], &data)) {
        return 0;
    }
    sha_update_chunks(ctxu.c, &data, sha2xx_chunk);
    return 1;
}

static ERL_NIF_TERM
hd224_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ContextUnion ctxu;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    if (!enif_get_resource(env, argv[0], ctx_type, &ctxu.v)) {
        return enif_make_badarg(env);
    }
    return context_fini(env, ctxu.c, DIGEST_SIZE_224, sha2xx_chunk);
}

static ERL_NIF_TERM
sha224(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return sha(env, argc, argv, hd224_init, hd2xx_update, hd224_final);
}

static ERL_NIF_TERM
sha224_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd224_init(env, argc, argv);
}

static ERL_NIF_TERM
sha224_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd2xx_update(env, argc, argv) ? argv[0] : enif_make_badarg(env);
}

static ERL_NIF_TERM
sha224_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd224_final(env, argc, argv);
}

static ERL_NIF_TERM
hd256_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM result;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    Context* ctx = (Context*)enif_alloc_resource(ctx_type, sizeof(Context));
    context_init(ctx, H256, sizeof H256, PADDED_SIZE_2XX);
    result = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return result;
}

static ERL_NIF_TERM
hd256_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ContextUnion ctxu;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    if (!enif_get_resource(env, argv[0], ctx_type, &ctxu.v)) {
        return enif_make_badarg(env);
    }
    return context_fini(env, ctxu.c, DIGEST_SIZE_256, sha2xx_chunk);
}

static ERL_NIF_TERM
sha256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return sha(env, argc, argv, hd256_init, hd2xx_update, hd256_final);
}

static ERL_NIF_TERM
sha256_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd256_init(env, argc, argv);
}

static ERL_NIF_TERM
sha256_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd2xx_update(env, argc, argv) ? argv[0] : enif_make_badarg(env);
}

static ERL_NIF_TERM
sha256_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd256_final(env, argc, argv);
}

static void
sha5xx_chunk(Context* ctx, unsigned char* chunk)
{
    uint64_t* hash = (uint64_t*)ctx->digest.data;
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t words[80];
    int i;
#ifndef WORDS_BIGENDIAN
    {
        uint64_t* from = (uint64_t*)chunk;
        for (i = 0; i < 16; ++i) {
            words[i] = BYTESWAP64(from[i]);
        }
    }
#else
    memcpy(words, chunk, 16*sizeof(*words));
#endif
    for (i = 16; i < sizeof(words)/sizeof(*words); ++i) {
        uint64_t w15 = words[i-15], w2 = words[i-2];
        uint64_t s0 = SM_SIGMA512_0(w15), s1 = SM_SIGMA512_1(w2);
        uint64_t w7 = words[i-7], w16 = words[i-16];
        words[i] = s1 + w7 + s0 + w16;
    }
    a = hash[0]; b = hash[1]; c = hash[2]; d = hash[3];
    e = hash[4]; f = hash[5]; g = hash[6]; h = hash[7];
    for (i = 0; i < sizeof(words)/sizeof(*words); ++i) {
        uint64_t t1, t2;
        t1 = h + BIG_SIGMA512_1(e) + CH(e,f,g) + K512[i] + words[i];
        t2 = BIG_SIGMA512_0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
    hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
}

static ERL_NIF_TERM
hd384_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM result;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    Context* ctx = (Context*)enif_alloc_resource(ctx_type, sizeof(Context));
    context_init(ctx, H384, sizeof H384, PADDED_SIZE_5XX);
    result = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return result;
}

static int
hd5xx_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary data;
    ContextUnion ctxu;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    if (!enif_get_resource(env, argv[0], ctx_type, &ctxu.v)) {
        return 0;
    }
    if (!enif_inspect_iolist_as_binary(env, argv[1], &data)) {
        return 0;
    }
    sha_update_chunks(ctxu.c, &data, sha5xx_chunk);
    return 1;
}

static ERL_NIF_TERM
hd384_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ContextUnion ctxu;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    if (!enif_get_resource(env, argv[0], ctx_type, &ctxu.v)) {
        return enif_make_badarg(env);
    }
    return context_fini(env, ctxu.c, DIGEST_SIZE_384, sha5xx_chunk);
}

static ERL_NIF_TERM
sha384(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return sha(env, argc, argv, hd384_init, hd5xx_update, hd384_final);
}

static ERL_NIF_TERM
sha384_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd384_init(env, argc, argv);
}

static ERL_NIF_TERM
sha384_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd5xx_update(env, argc, argv) ? argv[0] : enif_make_badarg(env);
}

static ERL_NIF_TERM
sha384_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd384_final(env, argc, argv);
}

static ERL_NIF_TERM
hd512_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ERL_NIF_TERM result;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    Context* ctx = (Context*)enif_alloc_resource(ctx_type, sizeof(Context));
    context_init(ctx, H512, sizeof H512, PADDED_SIZE_5XX);
    result = enif_make_resource(env, ctx);
    enif_release_resource(ctx);
    return result;
}

static ERL_NIF_TERM
hd512_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ContextUnion ctxu;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);
    if (!enif_get_resource(env, argv[0], ctx_type, &ctxu.v)) {
        return enif_make_badarg(env);
    }
    return context_fini(env, ctxu.c, DIGEST_SIZE_512, sha5xx_chunk);
}

static ERL_NIF_TERM
sha512(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return sha(env, argc, argv, hd512_init, hd5xx_update, hd512_final);
}

static ERL_NIF_TERM
sha512_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd512_init(env, argc, argv);
}

static ERL_NIF_TERM
sha512_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd5xx_update(env, argc, argv) ? argv[0] : enif_make_badarg(env);
}

static ERL_NIF_TERM
sha512_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return hd512_final(env, argc, argv);
}

static ErlNifFunc funcs[] = {
    {"sha224", 1, sha224},
    {"sha224_init", 0, sha224_init},
    {"sha224_update", 2, sha224_update},
    {"sha224_final", 1, sha224_final},
    {"sha256", 1, sha256},
    {"sha256_init", 0, sha256_init},
    {"sha256_update", 2, sha256_update},
    {"sha256_final", 1, sha256_final},
    {"sha384", 1, sha384},
    {"sha384_init", 0, sha384_init},
    {"sha384_update", 2, sha384_update},
    {"sha384_final", 1, sha384_final},
    {"sha512", 1, sha512},
    {"sha512_init", 0, sha512_init},
    {"sha512_update", 2, sha512_update},
    {"sha512_final", 1, sha512_final},
};

static void
context_dtor(ErlNifEnv* env, void* obj)
{
    Context* ctx = (Context*)obj;
    if (ctx != NULL && ctx->digest.size > 0) {
        enif_release_binary(&ctx->digest);
    }
}

static int
nifload(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    *priv_data = enif_open_resource_type(
        env,
        NULL,
        "erlsha2_context",
        context_dtor,
        ERL_NIF_RT_CREATE|ERL_NIF_RT_TAKEOVER,
        NULL
    );
    return 0;
}

ERL_NIF_INIT(erlsha2, funcs, nifload, NULL, NULL, NULL)
