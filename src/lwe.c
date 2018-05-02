#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/random.h>

#include <gmp.h>

#include "lwe.h"


void dot_product(mpz_t rop, mpz_t modulus, mpz_t a[], mpz_t b[], size_t len)
{
  mpz_set_ui(rop, 0);
  for (size_t i = 0; i < len; i++) {
    mpz_addmul(rop, a[i], b[i]);
  }
  mpz_mod(rop, rop, modulus);
}

gamma_t param_gen_from_seed(rseed_t rseed)
{
  gamma_t gamma;
  mpz_init(gamma.p);
  mpz_set_ui(gamma.p, 0xfffffffb);

  // mpz_init_set_str
  mpz_init(gamma.q);
  mpz_ui_pow_ui(gamma.q, 2, 736);

  gamma.log_sigma = 650;
  gamma.n = GAMMA_N;
  gamma.d = GAMMA_D;

  gmp_randinit_default(gamma.rstate);

  mpz_t mpz_rseed;
  mpz_init(mpz_rseed);
  mpz_import(mpz_rseed, 32, 1, sizeof(rseed[0]), 0, 0, rseed);
  gmp_randseed(gamma.rstate, mpz_rseed);
  mpz_clear(mpz_rseed);

  memmove(gamma.rseed, rseed, sizeof(rseed_t));
  return gamma;
}

gamma_t param_gen()
{
  rseed_t rseed;
  getrandom(&rseed, sizeof(rseed_t), GRND_NONBLOCK);
  return param_gen_from_seed(rseed);
}

void param_clear(gamma_t *g)
{
  mpz_clear(g->q);
  mpz_clear(g->p);
  gmp_randclear(g->rstate);
}


void key_gen(sk_t sk, gamma_t gamma)
{
  for (size_t i = 0; i < gamma.n; i++) {
    mpz_init(sk[i]);
    mpz_urandomm(sk[i], gamma.rstate, gamma.q);
  }
}

void key_clear(sk_t sk, gamma_t gamma)
{
  mpz_clearv(sk, gamma.n);
}

void ct_init(ct_t ct)
{
  mpz_initv(ct, GAMMA_N + 1);
}

void ct_clear(ct_t ct)
{
  mpz_clearv(ct, GAMMA_N + 1);
}

void errdist_uniform(mpz_t e, gamma_t gamma)
{
  mpz_urandomb(e, gamma.rstate, gamma.log_sigma + 4);

  const mp_bitcnt_t bit_pos = gamma.log_sigma + 3;
  if (mpz_tstbit(e, bit_pos)) mpz_mul_si(e, e, -1);
  mpz_clrbit(e, bit_pos);
}

void encrypt1(ct_t c, gamma_t gamma, gmp_randstate_t rs, sk_t sk, mpz_t m, void (*chi)(mpz_t, gamma_t))
{
  assert(mpz_cmp(gamma.p, m) > 0);

  // sample the error
  mpz_t e;
  mpz_init(e);
  (*chi)(e, gamma);

  mpz_mul(c[GAMMA_N], e, gamma.p);

  // sample a
  for (size_t i=0; i < GAMMA_N; i++) {
    mpz_urandomm(c[i], rs, gamma.q);
  }

  dot_product(c[GAMMA_N], gamma.q, sk, c, GAMMA_N);
  mpz_add(c[GAMMA_N], c[GAMMA_N], m);
  mpz_mod(c[GAMMA_N], c[GAMMA_N], gamma.q);

  mpz_clear(e);
}

void decompress_encryption(ct_t c, gamma_t gamma, gmp_randstate_t rs, mpz_t b)
{
  size_t i = 0;
  while (i++ < GAMMA_N) {
    mpz_urandomm(c[i], rs, gamma.q);
  }

  mpz_set(c[i], b);
}

void decrypt(mpz_t m, gamma_t gamma, sk_t sk, ct_t ct)
{
  dot_product(m, gamma.q, ct, sk, GAMMA_N);
  mpz_sub(m, ct[GAMMA_N], m);
  mpz_mod(m, m, gamma.q);
  mpz_mod(m, m, gamma.p);
}

void eval(ct_t rop, gamma_t gamma, ct_t c[], mpz_t coeff[], size_t d)
{
  for (size_t i = 0; i != GAMMA_N+1; i++) {
    mpz_set_ui(rop[i], 0);
    for (size_t j = 0; j != d; j++) {
      mpz_addmul(rop[i], c[j][i], coeff[j]);
    }
    mpz_mod(rop[i], rop[i], gamma.q);
  }
}
