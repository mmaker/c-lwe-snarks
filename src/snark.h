#pragma once
#include <stdbool.h>
#include "lwe.h"
#include "entropy.h"

#define CRS_SIZE (CT_BYTES * (2*GAMMA_D + GAMMA_M + 1 + 2))

#define CRS_S_OFFSET(i)   ((i) * CT_BYTES)
#define CRS_AS_OFFSET(i)  (((i) * CT_BYTES) + (CT_BYTES * GAMMA_D))
#define CRS_T_OFFSET()    (2 * (CT_BYTES * GAMMA_D))
#define CRS_V_OFFSET(i)   (2 * (CT_BYTES * GAMMA_D) + CT_BYTES + (i) * CT_BYTES)


#define CRS_S_EXPORT(crs, i, ct)  ct_export(crs->s[i], ct)
#define CRS_AS_EXPORT(crs, i, ct) ct_export(crs->as[i], ct)
#define CRS_T_EXPORT(crs, ct)     ct_export(crs->t, ct)
#define CRS_V_EXPORT(crs, i, ct)  ct_export(crs->v[i], ct)

#define CRS_T_IMPORT(ct, rng, crs)  do {          \
    const size_t pos = CRS_T_OFFSET();            \
    rng_seek(pos);                                \
    ct_import(ct, rng, &crs->stream[pos]);        \
  } while (0)


#define CRS_V_IMPORT(ct, rng, crs, i) do {      \
  const size_t pos = CRS_V_OFFSET(i);           \
  rng_seek(pos);                                \
  ct_import(ct, rng, &crs->stream[pos]);        \
  } while (0)


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
