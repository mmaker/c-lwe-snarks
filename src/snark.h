#pragma once
#include <stdbool.h>
#include "lwe.h"

#define CRS_SIZE (CT_BYTES * (2*GAMMA_D + GAMMA_M + 1 + 2))

#define crs_s_offset(i) ((i) * CT_BLOCK)
#define crs_as_offset(i)(((i) * CT_BLOCK) + (CT_BLOCK * GAMMA_D))
#define crs_t_offset (2 * (CT_BLOCK * GAMMA_D))
#define crs_v_offset(i) (2 * (CT_BLOCK * GAMMA_D) + CT_BLOCK + (i) * CT_BLOCK)


struct proof {
  ct_t h;
  ct_t hat_h;
  ct_t hat_v;
  ct_t v_w;
  ct_t b_w;
};

typedef struct proof proof_t[1];

struct vrs {
  uint64_t alpha;
  uint64_t beta;
  uint64_t s;

  sk_t sk;
};
typedef struct vrs vrs_t[1];

void proof_init(proof_t pi);
void proof_clear(proof_t pi);

void setup(uint8_t *crs, vrs_t vrs, uint8_t *ssp, rng_t rng);
void prover(proof_t pi, uint8_t *crs, uint8_t *ssp, mpz_t witness, rng_t rng);
bool verifier(uint8_t *ssp, vrs_t vrs, proof_t pi);
