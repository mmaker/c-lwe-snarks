#pragma once
#include <stdbool.h>
#include "lwe.h"

struct __crs {
  rseed_t rseed;
  mpz_t s[GAMMA_D];
  mpz_t alpha_s[GAMMA_D+1];
  mpz_t beta_t;
  mpz_t beta_v[GAMMA_D];
};

struct __vk {
  sk_t sk;
  mpz_t s;
  mpz_t alpha;
  mpz_t beta;
};


typedef struct __vk vk_t[1];
typedef struct __crs crs_t[1];
typedef struct __ctx proof_t[5];

void crs_gen(crs_t crs, vk_t vk, gamma_t gamma, int ssp_fd);
void crs_clear(crs_t crs, gamma_t gamma);
void vk_clear(vk_t vk, gamma_t gamma);

bool verifier(gamma_t gamma, vk_t vk, proof_t proof);


#define mpz_mul_mod(rop, a, b, mod) do {              \
    mpz_mul(rop, a, b);                               \
    mpz_mod(rop, rop, mod);                           \
  } while (0)
