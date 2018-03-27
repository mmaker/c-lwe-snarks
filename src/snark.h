#pragma once
#include "lwe.h"

struct __crs {
  ctx_t s[GAMMA_D];
  ctx_t alpha_s[GAMMA_D+1];
  ctx_t beta_t;
  ctx_t beta_v[GAMMA_D];
};


typedef struct __crs crs_t[1];

struct __vk {
  sk_t sk;
  mpz_t s;
  mpz_t alpha;
  // mpz_t beta;
};


typedef struct __vk vk_t[1];

void crs_gen(crs_t crs, vk_t vk, gamma_t gamma);
void crs_clear(crs_t crs, gamma_t gamma);
void vk_clear(vk_t vk, gamma_t gamma);

#define mpz_mul_mod(rop, a, b, mod) do {              \
    mpz_mul(rop, a, b);                               \
    mpz_mod(rop, rop, mod);                           \
  } while (0)
