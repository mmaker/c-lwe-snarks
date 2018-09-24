#include <gmp.h>
#include "entropy.h"

gmp_randstate_t _rstate;
unsigned long int _rseed;

void mpz_entropy_init()
{
  gmp_randinit_default(_rstate);
  getrandom(&_rseed, sizeof(unsigned long int), GRND_NONBLOCK);
  gmp_randseed_ui(_rstate, _rseed);
}

void mpz2_urandomb(mpz_ptr rop, rng_t rstate, mp_bitcnt_t nbits)
 {
   mp_ptr rp;
   mp_size_t size;

   size = nbits / 8;
   rp = MPZ_NEWALLOC (rop, size);

   /*  TODO: AES */
   /* _gmp_rand (rp, rstate, nbits); */
   MPN_NORMALIZE (rp, size);
   SIZ (rop) = size;
 }
