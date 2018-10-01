#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "lwe.h"
#include "ssp.h"
#include "snark.h"
#include "tests.h"

void test_snark()
{
  rng_t rng;
  //int crsfd = open(CRS_FILENAME, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
  //uint8_t *crs = mmap(NULL, CRS_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, crsfd, 0);
  crs_t crs;
  crs_init(crs);
  // SSP GENERATION
  uint8_t *ssp = calloc(1, SSP_SIZE);
  mpz_t witness;
  mpz_init(witness);
  random_ssp(witness, ssp);

  // CRS GENERATION TEST
  vrs_t vrs;
  setup(crs, vrs, ssp);
  rng_init(rng, crs->seed);

  ct_t ct_s, ct_as;
  ct_init(ct_s);
  ct_init(ct_as);
  rng_seek(rng, CTR_S);
  ct_import(ct_s, rng, crs->s[0]);
  rng_seek(rng, CTR_AS);
  ct_import(ct_as, rng, crs->as[0]);
  mpz_t s, as;
  mpz_inits(s, as, NULL);
  regev_decrypt(s, vrs->sk, ct_s);
  regev_decrypt(as, vrs->sk, ct_as);
  assert(!mpz_cmp_ui(s, 1));
  assert(!mpz_cmp_ui(as, vrs->alpha));


  rng_seek(rng, CTR_S + CTR_CT);
  ct_import(ct_s, rng, crs->s[1]);
  rng_seek(rng, CTR_AS + CTR_CT);
  ct_import(ct_as, rng, crs->as[1]);
  regev_decrypt(s, vrs->sk, ct_s);
  regev_decrypt(as, vrs->sk, ct_as);
  mpz_mul_ui(s, s, vrs->alpha);
  mpz_mod_ui(s, s, GAMMA_P);
  assert(!mpz_cmp(s, as));

  rng_seek(rng, CTR_S + CTR_CT *(GAMMA_D-1));
  ct_import(ct_s, rng, crs->s[GAMMA_D-1]);
  rng_seek(rng, CTR_AS + CTR_CT *(GAMMA_D-1));
  ct_import(ct_as, rng, crs->as[GAMMA_D-1]);
  regev_decrypt(s, vrs->sk, ct_s);
  regev_decrypt(as, vrs->sk, ct_as);
  mpz_mul_ui(s, s, vrs->alpha);
  mpz_mod_ui(s, s, GAMMA_P);
  assert(!mpz_cmp(s, as));

  mpz_clears(s, as, NULL);
  ct_clear(ct_s);
  ct_clear(ct_as);

  // PROVER TESTS
  proof_t pi;
  proof_init(pi);
  prover(pi, crs, ssp, witness);

  mpz_t h_s, hat_h_s;
  mpz_inits(h_s, hat_h_s, NULL);
  regev_decrypt(h_s, vrs->sk, pi->h);
  regev_decrypt(hat_h_s, vrs->sk, pi->hat_h);
  mpz_mul_ui(h_s, h_s, vrs->alpha);
  mpz_mod_ui(h_s, h_s, GAMMA_P);
  assert(mpz_cmp_ui(h_s, 0) > 0 && mpz_cmp_ui(h_s, GAMMA_P) < 0);
  assert(!mpz_cmp(h_s, hat_h_s));
  mpz_clears(h_s, hat_h_s, NULL);

  nmod_poly_t v_i;
  mpz_t b_s, w_s;
  mpz_inits(b_s, w_s, NULL);
  nmod_poly_init(v_i, GAMMA_P);
  nmod_poly_import(&v_i, &ssp[ssp_t_offset], GAMMA_D);
  regev_decrypt(b_s, vrs->sk, pi->b_w);
  regev_decrypt(w_s, vrs->sk, pi->v_w);
  mpz_mul_ui(w_s, w_s, vrs->beta);
  mpz_mod_ui(w_s, w_s, GAMMA_P);
  //  assert(!mpz_cmp(w_s, b_s));
  mpz_clears(b_s, w_s, NULL);
  nmod_poly_clear(v_i);

  // VERIFIER TESTS
  bool out = verifier(ssp, vrs, pi);

  assert(out);
  proof_clear(pi);
  crs_clear(crs);
  free(ssp);
  key_clear(vrs->sk);
  rng_clear(rng);
  mpz_clear(witness);
  //munmap(crs, crs_length);
  //close(crsfd);
}


int main() {
  test_snark();
}
