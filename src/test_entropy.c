#include "config.h"

#include <assert.h>

#include "entropy.h"
#include "tests.h"


int main()
{
  rng_t prg;
  RNG_INIT(prg);

  mpz_t a;
  mpz_init(a);
  mpz2_urandomb(a, prg, 736);

  assert(mpz_cmp_ui(a, 0));
  mpz_clear(a);
  rng_clear(prg);
}
