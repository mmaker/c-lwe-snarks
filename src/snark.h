#pragma once
#include <stdbool.h>
#include "lwe.h"



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

void setup(uint8_t *crs, vrs_t vrs, int ssp_fd, gamma_t gamma);
void prover(proof_t pi, uint8_t *crs, int ssp_fd, mpz_t witness, gamma_t gamma);
bool verifier(gamma_t gamma, int ssp_fd, vrs_t vrs, proof_t pi);
