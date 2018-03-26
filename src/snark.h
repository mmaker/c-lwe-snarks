#pragma once
#include "lwe.h"

typedef struct crs {
  ctx_t s[GAMMA_D];
  ctx_t alpha_s[GAMMA_D+1];
  ctx_t beta_t;
  ctx_t beta_v[GAMMA_D];
} crs_t;

typedef struct vk {
  sk_t sk;
  //  mpz_t alpha;
  // mpz_t beta;
} vk_t;


void crs_gen(crs_t* crs, vk_t* vk, gamma_t gamma);
