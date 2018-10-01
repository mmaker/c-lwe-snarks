#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/mman.h>

#include <flint/nmod_poly.h>
#include <gmp.h>

#include "lwe.h"
#include "entropy.h"

void mpz_add_dotp(mpz_t rop,
                  mpz_t a[static 1], mpz_t b[static 1],
                  size_t len)
{
  for (size_t i = 0; i < len; i++) {
    mpz_addmul(rop, a[i], b[i]);
  }
  modq(rop);
}

void key_gen(sk_t sk)
{
  mpz_initv(sk, GAMMA_N);
  mpz2_urandombv2(sk, GAMMA_LOGQ, GAMMA_N);
}

void key_clear(sk_t sk)
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

static inline void mpz_randomsgn(mpz_t dst, const mpz_t src)
{
  uint8_t sign;
  getrandom(&sign, 1, GRND_NONBLOCK);
  if (sign & 0x01) {
    mpz_neg(dst, src);
  }
}

void errdist_uniform(mpz_t e)
{
  mpz2_urandomb2(e, GAMMA_LOG_SIGMA+3);
}

void ct_smudge(ct_t ct) {
  mpz_t smudging;
  mpz_init(smudging);

  mpz2_urandomb2(smudging, GAMMA_LOG_SMUDGING);
  mpz_randomsgn(smudging, smudging);
  mpz_mul_ui(smudging, smudging, GAMMA_P);

  mpz_add(ct[GAMMA_N], ct[GAMMA_N], smudging);
  modq(ct[GAMMA_N]);
  mpz_clear(smudging);
}

void regev_encrypt2(ct_t c, rng_t rs, sk_t sk, mpz_t m, void (*chi)(mpz_t))
{
  assert(mpz_cmp_ui(m, GAMMA_P) < 0);

  // sample the error
  mpz_t e;
  mpz_init(e);
  (*chi)(e);
  mpz_mul_ui(c[GAMMA_N], e, GAMMA_P);
  mpz_randomsgn(e, e);

  // sample a
  mpz2_urandommv(c, rs, GAMMA_LOGQ, GAMMA_N);

  mpz_add_dotp(c[GAMMA_N], sk, c, GAMMA_N);
  mpz_add(c[GAMMA_N], c[GAMMA_N], m);
  modq(c[GAMMA_N]);

  mpz_clear(e);
}

void decompress_encryption(ct_t c, rng_t rng, mpz_t b)
{
  mpz2_urandommv(c, rng, GAMMA_LOGQ, GAMMA_N);
  mpz_set(c[GAMMA_N], b);
}

void regev_decrypt(mpz_t m, sk_t sk, ct_t ct)
{
  mpz_dotp(m, ct, sk, GAMMA_N);
  mpz_neg(m, m);
  mpz_add(m, ct[GAMMA_N], m);
  mpz_mod_ui(m, m, GAMMA_P);
}



void ct_export(uint8_t *buf, ct_t ct)
{
  bzero(buf, CT_BLOCK);
  mpz_export(buf, NULL, -1, sizeof(uint8_t), -1, 0, ct[GAMMA_N]);
}


void ct_import(ct_t ct, rng_t rng, uint8_t *buf)
{
  mpz2_urandommv(ct, rng, GAMMA_LOGQ, GAMMA_N);
  mpz_import(ct[GAMMA_N], LOGQ_BYTES, -1, sizeof(uint8_t), -1, 0, buf);
}

/**
 * Compute the scalar product of a ciphertext (mod q) times a plaintext (mod p).
 */
void ct_mul_ui(ct_t rop, ct_t a, uint64_t b)
{
  assert(b < GAMMA_P);

  for (size_t i = 0; i <= GAMMA_N; i++) {
    mpz_mul_ui(rop[i], a[i], b);
    modq(rop[i]);
  }
}

void ct_addmul_ui(ct_t rop, ct_t a, uint64_t b)
{
  assert(b < GAMMA_P);

  for (size_t i = 0; i <= GAMMA_N; i++) {
    mpz_addmul_ui(rop[i], a[i], b);
    modq(rop[i]);
  }
}

void ct_add(ct_t rop, ct_t a, ct_t b)
{
  for (size_t i = 0; i <= GAMMA_N; i++) {
    mpz_add(rop[i], a[i], b[i]);
    modq(rop[i]);
  }
}


void ct_zero(ct_t rop)
{
  for (size_t i = 0; i <= GAMMA_N; i++) {
    mpz_set_ui(rop[i], 0);
  }
}

#define fail_if_error() do {                    \
    if (errno > 0) {                            \
      perror("Failed" __FILE__ );               \
      exit(EXIT_FAILURE);                       \
    }                                           \
  } while(0)



void eval_poly(ct_t rop, rng_t rng, uint8_t *c8, nmod_poly_t p, size_t d)
{
  ct_t ct;
  ct_init(ct);

  for (size_t i = 0; i < d; i++) {
    ct_import(ct, rng, &c8[i * CT_BLOCK]);
    ct_addmul_ui(rop, ct, nmod_poly_get_coeff_ui(p, i));
  }
  ct_clear(ct);
}
