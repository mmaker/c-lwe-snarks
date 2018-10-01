#include "config.h"

#include <assert.h>
#include <gmp.h>
#include "aes.h"
#include "entropy.h"



#define LIMBS_TO_BYTES(n) (n * sizeof(mp_limb_t))
void mpz2_urandomb(mpz_ptr rop, rng_t prg, size_t nbits)
{
  // Let's support this to byte-level please.
  //  assert(nbits % 8 == 0);

  mp_ptr rp;
  size_t limbs = BITS_TO_LIMBS(nbits);
  const size_t bytes = nbits / 8;

  rp = MPZ_NEWALLOC(rop, limbs);

  aesctr_prg((aesctr_ptr) prg, rp, bytes);
  rp[limbs-1] &= (0xFFFFFFFFFFFFFFFFUL >> (limbs * 64 - nbits));
  MPN_NORMALIZE(rp, limbs);
  SIZ(rop) = limbs;
}

void mpz2_urandomb2(mpz_ptr rop, size_t nbits)
{
  // Let's support this to byte-level please.
  //  assert(nbits % 8 == 0);

  mp_ptr rp;
  size_t limbs = BITS_TO_LIMBS(nbits);
  const size_t bytes = nbits / 8;

  rp = MPZ_NEWALLOC(rop, limbs);

  getrandom(rp, bytes, GRND_NONBLOCK);
  rp[limbs-1] &= (0xFFFFFFFFFFFFFFFFUL >> (limbs * 64 - nbits));
  MPN_NORMALIZE(rp, limbs);
  SIZ(rop) = limbs;
}


void rng_seek(rng_t prg, size_t count)
{
  CTR(prg) = count/16;
  count -= CTR(prg) * 16;

  uint8_t sink[count];
  aesctr_prg((aesctr_ptr) prg, sink, count);
}

void rng_init(rng_t prg, uint8_t *rseed)
{
  aesctr_init((aesctr_ptr) prg, rseed + 8, *((uint64_t *) rseed));
}


void rng_clear(rng_t rng)
{
  aesctr_clear((aesctr_ptr) rng);
}
