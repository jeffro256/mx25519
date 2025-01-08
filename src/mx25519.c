/* Copyright (c) 2022 tevador <tevador@gmail.com>
 *
 * This file is part of mx25519, which is released under LGPLv3.
 * See LICENSE for full license details.
*/

#ifdef __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#ifdef __GNUC__
#define _GNU_SOURCE
#endif

#include <mx25519.h>

#include "impl.h"
#include "cpu.h"
#include "scalar.h"
#include "platform.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

/* Define WIPE32() depending on the platform */
#if __STDC_VERSION__ >= 202311L
  #define WIPE32(p) memset_explicit(p, 0, 32)
#elif defined(_DEFAULT_SOURCE) || defined(PLATFORM_BSD)
  #define WIPE32(p) explicit_bzero(p, 32)
#elif defined(__STDC_LIB_EXT1__)
  #define WIPE32(p) memset_s(p, 32, 0, 32)
#elif defined(PLATFORM_WIN)
  #include <windows.h>
  #define WIPE32(p) SecureZeroMemory(p, 32)
#else
  void wipe32_volatile(void *p) {
    /* https://github.com/jedisct1/libsodium/blob/7014b204/src/libsodium/sodium/utils.c#L149-L155 */
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) p;
    size_t i = (size_t) 0U;

    while (i < 32) {
        pnt_[i++] = 0U;
    }
  }
  #define WIPE32(p) wipe32_volatile(p)
#endif

static const mx25519_pubkey x25519_base = {
    .data = { 9 }
};

static bool impl_supported(mx25519_type impl) {
    if (impl == MX25519_TYPE_PORTABLE) {
        return true;
    }
    if (impl == MX25519_TYPE_ARM64) {
#if defined(PLATFORM_ARM64)
        return true;
#else
        return false;
#endif
    }
    if (impl == MX25519_TYPE_AMD64) {
#if defined(PLATFORM_AMD64)
        return true;
#else
        return false;
#endif
    }
    if (impl == MX25519_TYPE_AMD64X) {
#if defined(PLATFORM_AMD64)
        x25519_cpu_cap cap = mx25519_get_cpu_cap();
        return (cap & X25519_CPU_CAP_MULX) != 0
            && (cap & X25519_CPU_CAP_ADX)  != 0;
#else
        return false;
#endif
    }
    return false;
}

static mx25519_type select_best_impl(void) {
#if defined(PLATFORM_AMD64)
    if (impl_supported(MX25519_TYPE_AMD64X)) {
        return MX25519_TYPE_AMD64X;
    }
    return MX25519_TYPE_AMD64;
#elif defined(PLATFORM_ARM64)
    return MX25519_TYPE_ARM64;
#else
    return MX25519_TYPE_PORTABLE;
#endif
}

static void clamp_and_dispatch(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key,
    const mx25519_pubkey* pt, mx25519_unclamp_flags unclamp_flags)
{
    const uint8_t lsb_mask = 248 | ((unclamp_flags & MX25519_UNCLAMP_LSBS) * 7);
    const uint8_t msb_mask = (~unclamp_flags & MX25519_UNCLAMP_254) << 5;
    mx25519_privkey clamped_pkey;

    assert(impl != NULL);
    assert(pt != NULL);
    assert(key != NULL);
    assert(result != NULL);
    assert(impl->scmul != NULL);
    assert(impl->type <= MX25519_TYPE_AMD64X);
    assert(MX25519_UNCLAMP_NONE == 0);
    assert(MX25519_UNCLAMP_ALL == (MX25519_UNCLAMP_254 | MX25519_UNCLAMP_LSBS));

    /* clamp key */
    clamped_pkey.data[0] = key->data[0] & lsb_mask;
    for (int i = 1; i < 31; ++i)
        clamped_pkey.data[i] = key->data[i];
    clamped_pkey.data[31] = (key->data[31] | msb_mask) & 0x7f;

    /* dispatch */
    impl->scmul(result->data, clamped_pkey.data, pt->data);

    /* wipe clamped key, don't try to prevent swap-to-disk due to short life */
    WIPE32(clamped_pkey.data);
}

const mx25519_impl* mx25519_select_impl(mx25519_type type)
{
    if (type == MX25519_TYPE_AUTO) {
        type = select_best_impl();
    }
    else if (!impl_supported(type)) {
        return NULL;
    }
    assert(type >= 0 && type < 4);
    return mx25519_impls[type];
}

mx25519_type mx25519_impl_type(const mx25519_impl* impl)
{
    assert(impl != NULL);
    return impl->type;
}

void mx25519_scmul_base(const mx25519_impl* impl, mx25519_pubkey* result,
    const mx25519_privkey* key)
{
    clamp_and_dispatch(impl, result, key, &x25519_base, MX25519_UNCLAMP_NONE);
}

void mx25519_scmul_base_unclamped(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key,
    mx25519_unclamp_flags unclamp_flags)
{
    clamp_and_dispatch(impl, result, key, &x25519_base, unclamp_flags);
}

void mx25519_scmul_key(const mx25519_impl* impl, mx25519_pubkey* result,
    const mx25519_privkey* key, const mx25519_pubkey* pt)
{
    clamp_and_dispatch(impl, result, key, pt, MX25519_UNCLAMP_NONE);
}

void mx25519_scmul_key_unclamped(const mx25519_impl* impl,
    mx25519_pubkey* result, const mx25519_privkey* key,
    const mx25519_pubkey* pt, mx25519_unclamp_flags unclamp_flags)
{
    clamp_and_dispatch(impl, result, key, pt, unclamp_flags);
}

int mx25519_invkey(mx25519_privkey* invkey, const mx25519_privkey keys[],
    size_t num_keys)
{
    assert(invkey != NULL);
    assert(keys != NULL || num_keys == 0);

    /* calculate 8*key[0]*key[1]*... in Montgomery form */
    x25519_scalar_mont prod_mont = mx25519_sc8_mont;

    for (size_t i = 0; i < num_keys; ++i) {
        x25519_scalar key_sc;
        x25519_scalar_mont key_mont;
        mx25519_scalar_unpack(&key_sc, keys[i].data);
        key_sc.v[0] &= 0xfffffffffffffff8;
        key_sc.v[3] &= 0x7fffffffffffffff;
        mx25519_scalar_to_mont(&key_mont, &key_sc);
        mx25519_scalar_mul(&prod_mont, &prod_mont, &key_mont);
    }

    /* invert in Montgomery form */
    mx25519_scalar_inv(&prod_mont, &prod_mont);

    /* convert back from Montgomery form */
    x25519_scalar res;
    mx25519_scalar_from_mont(&res, &prod_mont);

    if (res.v[3] >= 0x1000000000000000) {
        return 1; /* inverse is larger than or equal to 2^252 */
    }

    /* shift left by 3 bits */
    mx25519_scalar_lsh3(&res);

    mx25519_scalar_pack(invkey->data, &res);
    return 0;
}
