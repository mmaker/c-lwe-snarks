#include "config.h"

#include <assert.h>
#include <gmp.h>
#include "aes.h"
#include "entropy.h"

gmp_randstate_t _rstate;
unsigned long int _rseed;


void mpz_entropy_init()
{
  gmp_randinit_default(_rstate);
  getrandom(&_rseed, sizeof(unsigned long int), GRND_NONBLOCK);
  gmp_randseed_ui(_rstate, _rseed);
}


#define LIMBS_TO_BYTES(n) (n * sizeof(mp_limb_t))
void mpz2_urandomb(mpz_ptr rop, rng_t prg, size_t nbits)
{
  // Let's support this to byte-level please.
  //  assert(nbits % 8 == 0);

  mp_ptr rp;
  size_t limbs = BITS_TO_LIMBS(nbits);

  rp = MPZ_NEWALLOC(rop, limbs);

  aesctr_prg((aesctr_ptr) prg, rp, LIMBS_TO_BYTES(limbs));
  rp[limbs-1] &= (0xFFFFFFFFFFFFFFFFUL >> (limbs * 64 - nbits));
  MPN_NORMALIZE(rp, limbs);
  SIZ(rop) = limbs;
}


void rng_init(rng_t prg, uint8_t *rseed)
{
  aesctr_init((aesctr_ptr) prg, rseed + 8, *((uint64_t *) rseed));
}


void rng_clear(rng_t rng)
{
  aesctr_clear((aesctr_ptr) rng);
}
