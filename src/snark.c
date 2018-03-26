#include <stdlib.h>

#include "lwe.h"
#include "snark.h"


#define mpz_mul_mod(rop, a, b, mod) do {              \
    mpz_mul(rop, a, b);                               \
    mpz_mod(rop, rop, mod);                           \
  } while (0)

void crs_gen(crs_t* crs, vk_t* vk, gamma_t gamma) {
  mpz_t alpha, s, ipow;
  mpz_inits(alpha, s, ipow, NULL);
  mpz_set_ui(ipow, 1);

  key_gen(vk->sk, gamma);

  mpz_urandomm(s, gamma.rstate, gamma.p);
  mpz_urandomm(alpha, gamma.rstate, gamma.p);

  for (size_t i = 0; i < gamma.d; i++) {
    ct_init(crs->s[i], gamma);
    mpz_mul_mod(ipow, ipow, s, gamma.p);
    encrypt(crs->s[i], gamma, vk->sk, ipow);
  }

  mpz_clears(alpha, s, ipow, NULL);
}

void crs_clear(crs_t* crs, gamma_t gamma)
{
  ct_clearv(crs->s, gamma.d, gamma);
}
