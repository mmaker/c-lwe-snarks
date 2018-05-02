#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
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
  mpz_set_ui(gamma.p, GAMMA_P);

  // mpz_init_set_str
  mpz_init(gamma.q);
  mpz_ui_pow_ui(gamma.q, 2, GAMMA_LOGQ);

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
  mpz_initv(sk, GAMMA_N);
  mpz_urandommv(sk, gamma.rstate, gamma.q, GAMMA_N);
}

void key_clear(sk_t sk, gamma_t gamma)
{
  mpz_clearv(sk, GAMMA_N);
}

void ct_init(ct_t ct)
{
  mpz_initv(ct, GAMMA_N+1);
}

void ct_clear(ct_t ct)
{
  mpz_clearv(ct, GAMMA_N+1);
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
  mpz_urandommv(c, rs, gamma.q, GAMMA_N);

  dot_product(c[GAMMA_N], gamma.q, sk, c, GAMMA_N);
  mpz_add(c[GAMMA_N], c[GAMMA_N], m);
  mpz_mod(c[GAMMA_N], c[GAMMA_N], gamma.q);

  mpz_clear(e);
}

void decompress_encryption(ct_t c, gamma_t gamma, gmp_randstate_t rs, mpz_t b)
{
  mpz_urandommv(c, rs, gamma.q, GAMMA_N);
  mpz_set(c[GAMMA_N], b);
}

void decrypt(mpz_t m, gamma_t gamma, sk_t sk, ct_t ct)
{
  dot_product(m, gamma.q, ct, sk, GAMMA_N);
  mpz_sub(m, ct[GAMMA_N], m);
  mpz_mod(m, m, gamma.q);
  mpz_mod(m, m, gamma.p);
}



void ct_export(uint8_t *buf, ct_t ct)
{
  bzero(buf, CT_BYTES);
  // export into file
  for (size_t i = 0; i < GAMMA_N+1; i++) {
    mpz_export(&buf[i*LOGQ_BYTES], NULL, -1, sizeof(uint8_t), -1, 0, ct[i]);
  }
}


void ct_import(ct_t ct, uint8_t *buf)
{
  for (size_t i = 0; i < GAMMA_N+1; i++) {
    mpz_import(ct[i], LOGQ_BYTES, -1, sizeof(uint8_t), -1, 0, &buf[i*LOGQ_BYTES]);
  }
}

/**
 * Compute the scalar product of a ciphertext (mod q) times a plaintext (mod p).
 */
void ct_mul_scalar(ct_t rop, gamma_t gamma, ct_t a, mpz_t b)
{
  for (size_t i = 0; i != GAMMA_N+1; i++) {
    mpz_mul(rop[i], a[i], b);
    mpz_mod(rop[i], rop[i], gamma.q);
  }
}

void ct_add(ct_t rop, gamma_t gamma, ct_t a, ct_t b)
{
  for (size_t i = 0; i != GAMMA_N+1; i++) {
    mpz_add(rop[i], a[i], b[i]);
    mpz_mod(rop[i], rop[i], gamma.q);
  }
}

void eval(ct_t rop, gamma_t gamma, uint8_t c8[], mpz_t coeff[], size_t d)
{
  ct_t ct;
  ct_init(ct);

  for (size_t i = 0; i != d; i++) {
    ct_import(ct, &c8[i * CT_BYTES]);
    ct_mul_scalar(ct, gamma, ct, coeff[i]);
    ct_add(rop, gamma, rop, ct);
  }
  ct_clear(ct);
}


void eval_fd(ct_t rop, gamma_t gamma, int cfd, mpz_t coeff[], size_t d)
{
  ct_t ct;
  ct_init(ct);

  uint8_t buf[CT_BYTES];

  for (size_t i = 0; i != d; i++) {
    read(cfd, buf, CT_BYTES);
    ct_import(ct, buf);
    ct_mul_scalar(ct, gamma, ct, coeff[i]);
    ct_add(rop, gamma, rop, ct);
  }
  ct_clear(ct);
}
