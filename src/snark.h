#pragma once
#include <stdbool.h>
#include "lwe.h"

#define CRS_SIZE (CT_BYTES * (2*GAMMA_D + GAMMA_M + 1 + 2))

#define CRS_S_OFFSET(crs, i) (&crs[(i) * CT_BLOCK])
#define CRS_AS_OFFSET(crs, i)(&crs[((i) * CT_BLOCK) + (CT_BLOCK * GAMMA_D)])
#define CRS_T_OFFSET(crs)    (&crs[2 * (CT_BLOCK * GAMMA_D)])
#define CRS_V_OFFSET(crs, i) (&crs[2 * (CT_BLOCK * GAMMA_D) + CT_BLOCK + (i) * CT_BLOCK])


struct proof {
  ct_t h;
  ct_t hat_h;
  ct_t hat_v;
  ct_t v_w;
  ct_t b_w;
};


struct vrs {
  uint64_t alpha;
  uint64_t beta;
  uint64_t s;

  sk_t sk;
};

typedef uint8_t *ssp_t;
typedef uint8_t *crs_t;
typedef struct proof proof_t[1];
typedef struct vrs vrs_t[1];

void proof_init(proof_t pi);
void proof_clear(proof_t pi);

void setup(uint8_t *crs, vrs_t vrs, ssp_t ssp, rng_t rng);
void prover(proof_t pi, crs_t crs, ssp_t ssp, mpz_t witness, rng_t rng);
bool verifier(uint8_t *ssp, vrs_t vrs, proof_t pi);
