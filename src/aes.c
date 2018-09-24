#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes.h"

#ifdef AESNI
#define MKRKEY256(rkeys, i, shuffle, rcon)	do {    \
    __m128i _s = rkeys[i-2];                          \
    __m128i _t = rkeys[i-1];                          \
    _s = _mm_xor_si128(_s, _mm_slli_si128(_s, 4));      \
    _s = _mm_xor_si128(_s, _mm_slli_si128(_s, 8));      \
    _t = _mm_aeskeygenassist_si128(_t, rcon);           \
    _t = _mm_shuffle_epi32(_t, shuffle);                \
    rkeys[i] = _mm_xor_si128(_s, _t);                   \
  } while (0)

static inline void
aes_encrypt_block_aesni(const uint8_t *in, uint8_t *out, aes_key_t *key)
{
    const __m128i *rkeys = key->rkeys;
    const size_t nr = 14;

    __m128i state;
    state = _mm_loadu_si128((const __m128i *)in);
    state = _mm_xor_si128(state, rkeys[0]);
    state = _mm_aesenc_si128(state, rkeys[1]);
    state = _mm_aesenc_si128(state, rkeys[2]);
    state = _mm_aesenc_si128(state, rkeys[3]);
    state = _mm_aesenc_si128(state, rkeys[4]);
    state = _mm_aesenc_si128(state, rkeys[5]);
    state = _mm_aesenc_si128(state, rkeys[6]);
    state = _mm_aesenc_si128(state, rkeys[7]);
    state = _mm_aesenc_si128(state, rkeys[8]);
    state = _mm_aesenc_si128(state, rkeys[9]);
    state = _mm_aesenc_si128(state, rkeys[10]);
    state = _mm_aesenc_si128(state, rkeys[11]);
    state = _mm_aesenc_si128(state, rkeys[12]);
    state = _mm_aesenc_si128(state, rkeys[13]);

    state = _mm_aesenclast_si128(state, rkeys[nr]);
    _mm_storeu_si128((__m128i *)out, state);
}
#endif

aesctr_t *aesctr_init(const uint8_t *key, const uint64_t nonce)
{
  aesctr_t *stream;
  stream = malloc(sizeof(aesctr_t));
  if (!stream) return NULL;
  stream->key = malloc(sizeof(aes_key_t));
  if (!stream->key) {
    free(stream);
    return NULL;
  }

#ifdef AESNI
  aes_key_t *kexp = stream->key;

  /* Figure out where to put the round keys. */
  size_t rkey_offset;
  rkey_offset = (uintptr_t)(kexp->rkeys_buf) % sizeof(__m128i);
  rkey_offset = (sizeof(__m128i) - rkey_offset) % sizeof(__m128i);
  kexp->rkeys = (void *)&kexp->rkeys_buf[rkey_offset];

  /* Compute round keys. */
  kexp->rkeys[0] = _mm_loadu_si128((const __m128i *)&key[0]);
  kexp->rkeys[1] = _mm_loadu_si128((const __m128i *)&key[16]);

  MKRKEY256(kexp->rkeys, 2, 0xff, 0x01);
  MKRKEY256(kexp->rkeys, 3, 0xaa, 0x00);
  MKRKEY256(kexp->rkeys, 4, 0xff, 0x02);
  MKRKEY256(kexp->rkeys, 5, 0xaa, 0x00);
  MKRKEY256(kexp->rkeys, 6, 0xff, 0x04);
  MKRKEY256(kexp->rkeys, 7, 0xaa, 0x00);
  MKRKEY256(kexp->rkeys, 8, 0xff, 0x08);
  MKRKEY256(kexp->rkeys, 9, 0xaa, 0x00);
  MKRKEY256(kexp->rkeys, 10, 0xff, 0x10);
  MKRKEY256(kexp->rkeys, 11, 0xaa, 0x00);
  MKRKEY256(kexp->rkeys, 12, 0xff, 0x20);
  MKRKEY256(kexp->rkeys, 13, 0xaa, 0x00);
  MKRKEY256(kexp->rkeys, 14, 0xff, 0x40);

  if (!stream) {
    memset(kexp, 0x0, sizeof(aes_key_t));
    free(kexp);

    return 0;
  }
#else
  // XXX: AES_set_encrypt_key returns something on error.
  AES_set_encrypt_key(key, 256, stream->key);
#endif
  stream->nonce = nonce;

  return stream;
}

void aesctr_prg(aesctr_t *stream, uint8_t *outbuf, size_t ctr_start, size_t ctr_end)
{
  uint8_t pblk[16];
  size_t pos;

  memcpy(pblk, &stream->nonce, 8);

  for (pos = ctr_start; pos < ctr_end; pos++) {
    memcpy(pblk + 8, &pos, 8);

#ifdef AESNI
    aes_encrypt_block_aesni(pblk, outbuf, stream->key);
#else
    AES_encrypt(pblk, outbuf, stream->key);
#endif
    outbuf += 16;
  }
}

void aesctr_clear(aesctr_t *stream)
{
  if (stream == NULL)
    return;

#ifdef AESNI
  memset(stream->key, 0x0, sizeof(aes_key_t));
#else
  memset(stream->key, 0x0, sizeof(AES_KEY));
#endif

  free(stream->key);

  memset(stream, 0x0, sizeof(aesctr_t));
  free(stream);
}
