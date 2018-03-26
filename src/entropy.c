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
