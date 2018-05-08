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
  gamma_t gamma = param_gen();

  //int crsfd = open(CRS_FILENAME, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
  //uint8_t *crs = mmap(NULL, CRS_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, crsfd, 0);
  uint8_t *crs = calloc(1, CRS_SIZE);
  // SSP GENERATION
  uint8_t *ssp = calloc(1, ssp_length);
  mpz_t witness;
  mpz_init(witness);
  random_ssp(witness, ssp, gamma);

  // CRS GENERATION TEST
  vrs_t vrs;
  setup(crs, vrs, ssp, gamma);

  ct_t ct_s, ct_as;
  ct_init(ct_s);
  ct_init(ct_as);
  ct_import(ct_s, &crs[s_offset(0)]);
  ct_import(ct_as, &crs[as_offset(0)]);
  mpz_t s, as;
  mpz_inits(s, as, NULL);
  regev_decrypt(s, gamma, vrs->sk, ct_s);
  regev_decrypt(as, gamma, vrs->sk, ct_as);
  assert(!mpz_cmp_ui(s, 1));
  assert(!mpz_cmp_ui(as, vrs->alpha));

  ct_import(ct_s, &crs[s_offset(1)]);
  ct_import(ct_as, &crs[as_offset(1)]);
  regev_decrypt(s, gamma, vrs->sk, ct_s);
  regev_decrypt(as, gamma, vrs->sk, ct_as);
  mpz_mul_ui(s, s, vrs->alpha);
  mpz_mod_ui(s, s, GAMMA_P);
  assert(!mpz_cmp(s, as));

  ct_import(ct_s, &crs[s_offset(GAMMA_D-1)]);
  ct_import(ct_as, &crs[as_offset(GAMMA_D-1)]);
  regev_decrypt(s, gamma, vrs->sk, ct_s);
  regev_decrypt(as, gamma, vrs->sk, ct_as);
  mpz_mul_ui(s, s, vrs->alpha);
  mpz_mod_ui(s, s, GAMMA_P);
  assert(!mpz_cmp(s, as));

  mpz_clears(s, as, NULL);
  ct_clear(ct_s);
  ct_clear(ct_as);

  // PROVER TESTS
  proof_t pi;
  proof_init(pi);
  prover(pi, crs, ssp, witness, gamma);

  mpz_t h_s, hat_h_s;
  mpz_inits(h_s, hat_h_s, NULL);
  regev_decrypt(h_s, gamma, vrs->sk, pi->h);
  regev_decrypt(hat_h_s, gamma, vrs->sk, pi->hat_h);
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
  regev_decrypt(b_s, gamma, vrs->sk, pi->b_w);
  regev_decrypt(w_s, gamma, vrs->sk, pi->v_w);
  mpz_mul_ui(w_s, w_s, vrs->beta);
  mpz_mod_ui(w_s, w_s, GAMMA_P);
  mpz_clears(b_s, w_s, NULL);
  nmod_poly_clear(v_i);

  // VERIFIER TESTS
  bool out = verifier(gamma, ssp, vrs, pi);

  assert(out);
  proof_clear(pi);
  free(crs);
  free(ssp);
  //munmap(crs, crs_length);
  //close(crsfd);
}


int main() {
  test_snark();
}
