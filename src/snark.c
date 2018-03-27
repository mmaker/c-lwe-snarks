#include <stdlib.h>

#include "lwe.h"
#include "snark.h"


void crs_gen(crs_t crs, vk_t vk, gamma_t gamma) {
  mpz_t alpha, s, s_i, alpha_s_i;
  mpz_inits(alpha, s, s_i, alpha_s_i, NULL);

  mpz_urandomm(s, gamma.rstate, gamma.p);
  mpz_urandomm(alpha, gamma.rstate, gamma.p);

  // XXX some of these can be removed.
  key_gen(vk->sk, gamma);
  mpz_inits(vk->s, vk->alpha, NULL);
  mpz_set(vk->s, s);
  mpz_set(vk->alpha, alpha);

  mpz_set_ui(s_i, 1);
  mpz_mul_mod(alpha_s_i, s_i, alpha, gamma.p);
  ct_init(crs->alpha_s[0], gamma);
  encrypt(crs->alpha_s[0], gamma, vk->sk, alpha_s_i);

  for (size_t i = 0; i < gamma.d; i++) {
    ct_init(crs->s[i], gamma);
    mpz_mul_mod(s_i, s_i, s, gamma.p);
    encrypt(crs->s[i], gamma, vk->sk, s_i);

    ct_init(crs->alpha_s[i+1], gamma);
    mpz_mul_mod(alpha_s_i, s_i, alpha, gamma.p);
    // XXX: change the error
    encrypt(crs->alpha_s[i+1], gamma, vk->sk, alpha_s_i);
  }

  mpz_clears(alpha, s, s_i, alpha_s_i, NULL);
}


void vk_clear(vk_t vk, gamma_t gamma)
{
  mpz_clear(vk->s);
  mpz_clear(vk->alpha);
  key_clear(vk->sk, gamma);
}
void crs_clear(crs_t crs, gamma_t gamma)
{
  ct_clearv(crs->s, gamma.d, gamma);
  ct_clearv(crs->alpha_s, gamma.d + 1, gamma);
}
