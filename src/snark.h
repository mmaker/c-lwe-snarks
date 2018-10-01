#pragma once
#include <stdbool.h>
#include "lwe.h"
#include "entropy.h"

#define CRS_SIZE (CT_BYTES * (2*GAMMA_D + GAMMA_M + 1 + 2))

#define CTR_CT (CT_BYTES * GAMMA_N)
#define CTR_S  0
#define CTR_AS (CTR_CT * GAMMA_D)
#define CTR_BT  (2 * CTR_CT * GAMMA_D)
#define CTR_BV  (2 * CTR_CT * GAMMA_D + CTR_CT)

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

struct crs {
  rseed_t seed;
  uint8_t (* s)[CT_BYTES];
  uint8_t (* as)[CT_BYTES];
  uint8_t (* v)[CT_BYTES];
  uint8_t *t;
};

typedef uint8_t *ssp_t;
typedef struct crs crs_t[1];
typedef struct proof proof_t[1];
typedef struct vrs vrs_t[1];

void crs_init(crs_t crs);
void crs_clear(crs_t crs);
void proof_init(proof_t pi);
void proof_clear(proof_t pi);

void setup(crs_t crs, vrs_t vrs, ssp_t ssp);
void prover(proof_t pi, crs_t crs, ssp_t ssp, mpz_t witness);
bool verifier(ssp_t ssp, vrs_t vrs, proof_t pi);
