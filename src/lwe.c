#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/random.h>
#include <sys/syscall.h>

#include <gmp.h>

#include "lwe.h"


void dot_product(mpz_t rop, mpz_t modulus, mpz_t a[], mpz_t b[], size_t len)
{
  mpz_set_ui(rop, 0);
  for (size_t i = 0; i < len; i++) {
    mpz_addmul(rop, a[i], b[i]);
  }
}

gamma_t param_gen()
{

  gamma_t gamma;
  mpz_init(gamma.p);
  mpz_set_ui(gamma.p, 469572863);

  // mpz_init_set_str
  mpz_init(gamma.q);
  mpz_ui_pow_ui(gamma.q, 2, 800);

  gamma.log_sigma = 650;
  gamma.n = GAMMA_N;
  gamma.d = GAMMA_D;

  uint64_t rseed;
  gmp_randinit_default(gamma.rstate);
  getrandom(&rseed, sizeof(uint64_t), GRND_NONBLOCK);
  gmp_randseed_ui(gamma.rstate, rseed);

  return gamma;
}


void param_clear(gamma_t *g)
{
  mpz_clear(g->q);
  mpz_clear(g->p);
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

void ct_init(ctx_t ct, gamma_t gamma)
{
  ct->a = malloc(sizeof(mpz_t) * gamma.n);
  for (size_t i = 0; i != gamma.n; i++) {
    mpz_init(ct->a[i]);
  }
  mpz_init(ct->b);
}

void ct_clear(ctx_t ct, gamma_t gamma)
{
  mpz_clear(ct->b);
  mpz_clearv(ct->a, gamma.n);
  free(ct->a);
}

void errdist_uniform(mpz_t e, gamma_t gamma)
{
  mpz_urandomb(e, gamma.rstate, gamma.log_sigma + 4);

  const mp_bitcnt_t bit_pos = gamma.log_sigma + 3;
  if (mpz_tstbit(e, bit_pos)) mpz_mul_si(e, e, -1);
  mpz_clrbit(e, bit_pos);
}

void encrypt1(ctx_t c, gamma_t gamma, sk_t sk, mpz_t m, void (*chi)(mpz_t, gamma_t))
{
  assert(mpz_cmp(gamma.p, m) > 0);

  // sample the error
  mpz_t e;
  mpz_init(e);
  (*chi)(e, gamma);

  mpz_mul(c->b, e, gamma.p);

  // sample a
  for (size_t i=0; i < gamma.n; i++) {
    mpz_urandomm(c->a[i], gamma.rstate, gamma.q);
  }

  dot_product(c->b, gamma.q, sk, c->a, gamma.n);
  mpz_add(c->b, c->b, m);
  mpz_mod(c->b, c->b, gamma.q);

  mpz_clear(e);
}

void decrypt(mpz_t m, gamma_t gamma, sk_t sk, ctx_t ct)
{
  dot_product(m, gamma.q, ct->a, sk, gamma.n);
  mpz_sub(m, ct->b, m);
  mpz_mod(m, m, gamma.q);
  mpz_mod(m, m, gamma.p);
}

void eval(ctx_t rop, gamma_t gamma, ctx_t c[], mpz_t *coeff, size_t d)
{
  for (size_t i = 0; i != gamma.n; i++) {
    mpz_set_ui(rop->a[i], 0);
    for (size_t j = 0; j != d; j++) {
      mpz_addmul(rop->a[i], c[j]->a[i], coeff[j]);
    }
    mpz_mod(rop->a[i], rop->a[i], gamma.q);
  }

  mpz_set_ui(rop->b, 0);
  for (size_t j = 0; j != d; j++) {
    mpz_addmul(rop->b, c[j]->b, coeff[j]);
  }
  mpz_mod(rop->b, rop->b, gamma.q);
}

void clear_lin_comb(mpz_t rop, mpz_t *m, mpz_t *coeffs, gamma_t gamma, size_t N)
{
  for (size_t i = 0; i != N; ++i) {
    mpz_addmul(rop, m[i], coeffs[i]);
  }
  mpz_mod(rop, rop, gamma.p);
}
