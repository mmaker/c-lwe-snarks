#pragma once
#include <assert.h>
#include <stdint.h>
#include <sys/random.h>

#include <flint/nmod_poly.h>
#include <gmp.h>


/* Parameter generation */

typedef uint8_t rseed_t[32];

typedef struct gamma {
  mpz_t q;
  gmp_randstate_t rstate;
  rseed_t rseed;
} gamma_t;

#define GAMMA_N 1470
#define GAMMA_LOGQ 736
#define GAMMA_P 0xfffffffbUL
#define GAMMA_D (1UL << 8)
/* must be divisible by 8 */
#define GAMMA_M (64)
#define GAMMA_LU 10
#define GAMMA_LOG_SMUDGING 640
#define GAMMA_LOG_SIGMA 556
#define LOGQ_BYTES 92
#define LOGP_BYTES 4
#define CT_BYTES (LOGQ_BYTES * (GAMMA_N+1))
/* CT_BLOCK is the block to be written on disk.
   Depending on the device it will need to be a power of 2 divisible by sizeof((void *)).
*/
#define CT_BLOCK CT_BYTES //(1 << 18)



gamma_t param_gen();
gamma_t param_gen_from_seed(rseed_t rseed);
void param_clear(gamma_t *g);

/* secret key generation */
typedef mpz_t sk_t[GAMMA_N];

void key_gen(sk_t sk, gamma_t gamma);
void key_clear(sk_t sk);


/* error distributions */
void errdist_uniform(mpz_t e, gamma_t gamma);

/* ciphertext */
typedef mpz_t ct_t[GAMMA_N+1];

void ct_init(ct_t ct);
void ct_clear(ct_t ct);

void ct_export(uint8_t *buf, ct_t ct);
void ct_import(ct_t ct, uint8_t *buf);

void decompress_encryption(ct_t c, gamma_t gamma, gmp_randstate_t rs, mpz_t b);
void regev_encrypt1(ct_t c, gamma_t gamma, gmp_randstate_t rs, sk_t sk, mpz_t m, void (*chi)(mpz_t, gamma_t));

void mpz_add_dotp(mpz_t rop, mpz_t modulus, mpz_t a[], mpz_t b[], size_t len);

static inline void mpz_dotp(mpz_t rop, mpz_t modulus, mpz_t a[], mpz_t b[], size_t len) {
  mpz_set_ui(rop, 0);
  mpz_add_dotp(rop, modulus, a, b, len);
}

static inline
void regev_encrypt(ct_t c, gamma_t gamma, gmp_randstate_t rs, sk_t sk, mpz_t m)
{
  regev_encrypt1(c, gamma, rs, sk, m, errdist_uniform);
}


void regev_decrypt(mpz_t m, gamma_t gamma, sk_t sk, ct_t ct);
void ct_smudge(ct_t ct, gamma_t gamma);
void ct_add(ct_t rop, gamma_t gamma, ct_t a, ct_t b);
void ct_mul_ui(ct_t rop, gamma_t gamma, ct_t a, uint64_t b);
void eval_fd(ct_t rop, gamma_t gamma, int cfd, mpz_t coeff[], size_t d);
void eval_poly(ct_t rop, gamma_t gamma, uint8_t *c8, nmod_poly_t coeffs, size_t d);

#define ct_clearv(vs, len) do {                     \
    for (size_t i = 0; i < len; i++) {              \
      ct_clear((vs)[i]);                            \
  }                                                 \
} while (0)


#define mpz_clearv(vs, len) do {                    \
  for (size_t i = 0; i < len; i++) {                \
    mpz_clear((vs)[i]);                             \
  }                                                 \
} while (0)

#define mpz_initv(vs, len) do {                 \
    for (size_t i = 0; i < len; i++) {          \
      mpz_init2((vs)[i], GAMMA_LOGQ);           \
    }                                           \
  } while (0)


#define mpz_urandommv(vs, rstate, bits, len) do {       \
    for (size_t i = 0; i < len; i++) {                      \
      mpz_urandomb(vs[i], rstate, bits);              \
    }                                                       \
} while (0)


static inline uint64_t rand_modp()
{
  uint64_t rop;
  getrandom(&rop, sizeof(rop), GRND_NONBLOCK);
  return rop % GAMMA_P;
}

static inline void modq(mpz_t a)
{
  static const int pos = (GAMMA_LOGQ / 64) ;
  if (a->_mp_size > pos) {
    a->_mp_d[pos] &= (1UL << 33) - 1;
  }
}
