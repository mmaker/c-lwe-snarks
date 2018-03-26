#include <stdint.h>
#include <gmp.h>

typedef struct gamma {
  mpz_t p;
  mpz_t q;
  uint64_t log_sigma;
  uint64_t n;
  gmp_randstate_t rstate;
} gamma_t;

#define GAMMA_N 1200

typedef struct ctx {
  mpz_t* a;
  mpz_t b;
} ctx_t;

typedef mpz_t sk_t[GAMMA_N];


gamma_t param_gen();
void param_del(gamma_t *g);
void key_gen(sk_t sk, gamma_t gamma);
void key_clear(sk_t sk, gamma_t gamma);
void ctx_init(ctx_t *ct, gamma_t gamma);
void ct_clear(ctx_t *ct, gamma_t gamma);
void encrypt(ctx_t *c, gamma_t gamma, sk_t sk, mpz_t m);
void decrypt(mpz_t m, gamma_t gamma, sk_t sk, ctx_t ct);
void eval(ctx_t *rop, gamma_t gamma, ctx_t *c, mpz_t *coeff, size_t d);
void clear_lin_comb(mpz_t rop, mpz_t *m, mpz_t *coeffs, gamma_t gamma, size_t N);
