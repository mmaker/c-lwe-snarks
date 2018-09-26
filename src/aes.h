#pragma once
#include "config.h"

#include <stdint.h>


#ifdef AESNI
#include <wmmintrin.h>

typedef struct aes_key {
    uint8_t rkeys_buf[15 * sizeof(__m128i) + (sizeof(__m128i) - 1)];
    __m128i *rkeys;
} aes_key_t;
#else
#include <openssl/aes.h>

typedef AES_KEY aes_key_t;
#endif


struct aesctr {
  uint64_t nonce;
  aes_key_t *key;

  uint64_t ctr;
};

typedef struct aesctr *aesctr_ptr;
typedef struct aesctr aesctr_t[1];


void aesctr_init(aesctr_ptr stream, const uint8_t *key, const uint64_t nonce);
void aesctr_prg(aesctr_ptr stream, void *outbuf, size_t count);
void aesctr_clear(aesctr_ptr stream);
