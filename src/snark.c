#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/random.h>

#include <gmp.h>
#include <flint/nmod_poly.h>

#include "lwe.h"
#include "ssp.h"
#include "snark.h"

void setup(uint8_t *crs, vrs_t vrs, uint8_t *ssp, rng_t rng)
{
  vrs->alpha = rand_modp();
  vrs->beta = rand_modp();
  vrs->s = rand_modp();
  key_gen(vrs->sk, rng);

  ct_t ct;
  ct_init(ct);

  mpz_t current;
  mpz_init(current);
  uint64_t s_i = 1;
  uint64_t as_i = vrs->alpha;

  for (size_t i = 0; i < GAMMA_D; i++) {
    mpz_set_ui(current, s_i);
    regev_encrypt(ct, rng, vrs->sk, current);
    ct_export(&crs[s_offset(i)], ct);

    mpz_set_ui(current, as_i);
    regev_encrypt(ct, rng, vrs->sk, current);
    ct_export(&crs[as_offset(i)], ct);

    s_i = (s_i * vrs->s) % GAMMA_P;
    as_i = (as_i * vrs->s) % GAMMA_P;
  }

  nmod_poly_t v_i;
  nmod_poly_init(v_i, GAMMA_P);

  // β t(s)
  nmod_poly_import(&v_i, &ssp[ssp_t_offset], GAMMA_D);
  const uint64_t v_i_bs = (nmod_poly_evaluate_nmod(v_i, vrs->s) * vrs->beta) % GAMMA_P;
  mpz_set_ui(current, v_i_bs);
  regev_encrypt(ct, rng, vrs->sk, current);
  ct_export(&crs[t_offset], ct);

  // β v_i
  for (size_t i = 0; i < GAMMA_M; i++) {
    nmod_poly_import(&v_i, &ssp[ssp_v_i_offset(i)], GAMMA_D);
    uint64_t v_i_bs = (nmod_poly_evaluate_nmod(v_i, vrs->s) * vrs->beta) % GAMMA_P;
    mpz_set_ui(current, v_i_bs);
    regev_encrypt(ct, rng, vrs->sk, current);
    ct_export(&crs[v_offset(i)], ct);
  }

  ct_clear(ct);
  nmod_poly_clear(v_i);
  mpz_clear(current);
}

void prover(proof_t pi, uint8_t *crs, uint8_t *ssp, mpz_t witness, rng_t rng)
{
  nmod_poly_t t;
  nmod_poly_init(t, GAMMA_P);
  nmod_poly_t v_i;
  nmod_poly_init(v_i, GAMMA_P);
  nmod_poly_t w;
  nmod_poly_init(w, GAMMA_P);
  nmod_poly_t h;
  nmod_poly_init(h, GAMMA_P);
  ct_t ct_v_i;
  ct_init(ct_v_i);

  nmod_poly_t one;
  nmod_poly_init(one, GAMMA_P);
  nmod_poly_set_coeff_ui(one, 0, 1);

  // read t(x)
  nmod_poly_import(&t, &ssp[ssp_t_offset], GAMMA_D);

  uint64_t delta = rand_modp();
  nmod_poly_scalar_mul_nmod(w, t, delta);

  ct_import(pi->b_w, &crs[t_offset]);
  ct_mul_ui(pi->b_w, pi->b_w, delta);

  for (size_t i = 1; i < GAMMA_M; i++) {
    if (mpz_tstbit(witness, i-1)) {
      nmod_poly_import(&v_i, &ssp[ssp_v_i_offset(i)], GAMMA_D);
      nmod_poly_add(w, w, v_i);

      ct_import(ct_v_i, &crs[v_offset(i)]);
      ct_add(pi->b_w, pi->b_w, ct_v_i);
    }
  }

  eval_poly(pi->v_w, crs+s_offset(0), w, GAMMA_D);

  // Assume l_u = 0 . So v(x) = v_0(x) + w(x).
  nmod_poly_import(&v_i, &ssp[ssp_v_i_offset(0)], GAMMA_D);
  nmod_poly_add(w, w, v_i);
  eval_poly(pi->hat_v, crs+as_offset(0), w, GAMMA_D);

  nmod_poly_set(h, w);
  nmod_poly_pow(h, h, 2);
  nmod_poly_sub(h, h, one);
  nmod_poly_div(h, h, t);

  eval_poly(pi->h, crs+s_offset(0), h, GAMMA_D);
  eval_poly(pi->hat_h, crs+as_offset(0), h, GAMMA_D);


  nmod_poly_clear(h);
  nmod_poly_clear(v_i);
  nmod_poly_clear(w);
  nmod_poly_clear(one);
  nmod_poly_clear(t);
  ct_clear(ct_v_i);

  /* smudge proof terms */
  ct_smudge(pi->h, rng);
  ct_smudge(pi->hat_h, rng);
  ct_smudge(pi->hat_v, rng);
  ct_smudge(pi->v_w, rng);
  ct_smudge(pi->v_w, rng);
}

bool verifier(uint8_t *ssp, vrs_t vrs, proof_t pi) {
  bool result = false;
  mpz_t h_s, hath_s, hatv_s, w_s, b_s, t_s, v_s;
  mpz_inits(h_s, hath_s, hatv_s, w_s, b_s, t_s, v_s, NULL);

  nmod_poly_t pp;
  nmod_poly_init(pp, GAMMA_P);
  /* t_s */
  nmod_poly_import(&pp, &ssp[ssp_t_offset], GAMMA_D);
  mpz_set_ui(t_s, nmod_poly_evaluate_nmod(pp, vrs->s));

  /* decrypt the proof */
  regev_decrypt(h_s, vrs->sk, pi->h);
  regev_decrypt(hath_s, vrs->sk, pi->hat_h);
  regev_decrypt(hatv_s, vrs->sk, pi->hat_v);
  regev_decrypt(w_s, vrs->sk, pi->v_w);
  regev_decrypt(b_s, vrs->sk, pi->b_w);

  mpz_t test;
  mpz_init(test);

  /* v_s is just v0 + w_s*/
  nmod_poly_import(&pp, &ssp[ssp_v_i_offset(0)], GAMMA_D);
  mpz_set_ui(v_s, nmod_poly_evaluate_nmod(pp, vrs->s));
  mpz_add(v_s, v_s, w_s);
  mpz_mod_ui(v_s, v_s, GAMMA_P);

  /*  eq-pke  */
  mpz_mul_ui(test, h_s, vrs->alpha);
  mpz_mod_ui(test, test, GAMMA_P);
  if (mpz_cmp(test, hath_s)) goto end;
  mpz_mul_ui(test, v_s, vrs->alpha);
  mpz_mod_ui(test, test, GAMMA_P);
  if (mpz_cmp(test, hatv_s)) goto end;
  /* eq-div */
  mpz_mul(test, v_s, v_s);
  mpz_sub_ui(test, test, 1);
  mpz_submul(test, h_s, t_s);
  mpz_mod_ui(test, test, GAMMA_P);
  if (mpz_sgn(test)) goto end;
  /* eq-lin */
  mpz_mul_ui(test, w_s, vrs->beta);
  mpz_mod_ui(test, test, GAMMA_P);
  if (mpz_cmp(test, b_s)) goto end;

  /* test-error procedure */
  mpz_dotp(test, pi->b_w, vrs->sk, GAMMA_N);
  mpz_neg(test, test);
  mpz_cdiv_q_ui(test, test, GAMMA_P);
  if (SIZ(test) >= GAMMA_LOG_SMUDGING/8) goto end;

  result = true;

 end:
  mpz_clears(h_s, hath_s, hatv_s, w_s, b_s, t_s, v_s, NULL);
  mpz_clear(test);
  nmod_poly_clear(pp);
  return result;
}
