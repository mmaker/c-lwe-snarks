#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "lwe.h"
#include "snark.h"


void crs_gen(crs_t crs, vk_t vk, gamma_t gamma) {
  mpz_t alpha, s, s_i, alpha_s_i;
  mpz_inits(alpha, s, s_i, alpha_s_i, NULL);
  ctx_t ct;
  ct_init(ct, gamma);

  mpz_urandomm(s, gamma.rstate, gamma.p);
  mpz_urandomm(alpha, gamma.rstate, gamma.p);

  // XXX some of these can be removed.
  key_gen(vk->sk, gamma);
  mpz_inits(vk->s, vk->alpha, NULL);
  mpz_set(vk->s, s);
  mpz_set(vk->alpha, alpha);

  // create a new PRG that will be used to reproduce encryptions
  gmp_randstate_t rs;
  gmp_randinit_default(rs);
  rseed_t rseed;
  getrandom(&rseed, sizeof(rseed_t), GRND_NONBLOCK);
  mpz_t mpz_rseed;
  mpz_init(mpz_rseed);
  mpz_import(mpz_rseed, 32, 1, sizeof(rseed[0]), 0, 0, rseed);
  gmp_randseed(rs, mpz_rseed);
  mpz_clear(mpz_rseed);

  mpz_set_ui(s_i, 1);
  mpz_mul_mod(alpha_s_i, s_i, alpha, gamma.p);
  mpz_init(crs->alpha_s[0]);
  encrypt(ct, gamma, rs, vk->sk, alpha_s_i);
  mpz_set(crs->alpha_s[0], ct->b);

  for (size_t i = 0; i < gamma.d; i++) {
    mpz_init(crs->s[i]);
    mpz_mul_mod(s_i, s_i, s, gamma.p);
    encrypt(ct, gamma, rs, vk->sk, s_i);
    mpz_set(crs->s[i], ct->b);

    mpz_init(crs->alpha_s[i+1]);
    mpz_mul_mod(alpha_s_i, s_i, alpha, gamma.p);
    // XXX: change the error
    encrypt(ct, gamma, rs, vk->sk, alpha_s_i);
    mpz_set(crs->alpha_s[i+1], ct->b);
  }
  memmove(crs->rseed, rseed, sizeof(rseed_t));

  mpz_clears(alpha, s, s_i, alpha_s_i, NULL);
  ct_clear(ct, gamma);
}


void vk_clear(vk_t vk, gamma_t gamma)
{
  mpz_clear(vk->s);
  mpz_clear(vk->alpha);
  key_clear(vk->sk, gamma);
}
void crs_clear(crs_t crs, gamma_t gamma)
{
  mpz_clearv(crs->s, gamma.d);
  mpz_clearv(crs->alpha_s, gamma.d + 1);
}
