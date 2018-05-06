#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/random.h>

#include <flint/nmod_poly.h>

#include "lwe.h"
#include "ssp.h"
#include "snark.h"


#define s_offset(i) (i * CT_BYTES)
#define as_offset(i)  ((CT_BYTES * GAMMA_D) + (i * CT_BYTES))
#define v_offset(i) ((2)*(CT_BYTES * GAMMA_D) + i * CT_BYTES)

void setup(uint8_t *crs, vrs_t vrs, int ssp_fd, gamma_t gamma)
{
  vrs->alpha = rand_modp();
  vrs->beta = rand_modp();
  vrs->s = rand_modp();
  key_gen(vrs->sk, gamma);

  ct_t ct;
  ct_init(ct);

  mpz_t current;
  mpz_init(current);
  uint64_t s_i = 1;
  uint64_t as_i = vrs->alpha;

  for (size_t i = 0; i <= GAMMA_D; i++) {
    mpz_set_ui(current, s_i);
    regev_encrypt(ct, gamma, gamma.rstate, vrs->sk, current);
    ct_export(crs + s_offset(i), ct);

    mpz_set_ui(current, as_i);
    regev_encrypt(ct, gamma, gamma.rstate, vrs->sk, current);
    ct_export(crs + as_offset(i), ct);

    s_i = (s_i * vrs->s) % GAMMA_P;
    as_i = (as_i * vrs->s) % GAMMA_P;
  }

  uint8_t buf[8 * GAMMA_D];
  const size_t buflen = sizeof(buf);
  nmod_poly_t v_i;
  nmod_poly_init(v_i, GAMMA_P);
  for (size_t i = 0; i <= GAMMA_M+2; i++) {
    read(ssp_fd, buf, buflen);
    nmod_poly_import(&v_i, buf, GAMMA_D);
    uint64_t v_i_bs = (nmod_poly_evaluate_nmod(v_i, vrs->s) * vrs->beta) % GAMMA_P;
    mpz_set_ui(current, v_i_bs);
    regev_encrypt(ct, gamma, gamma.rstate, vrs->sk, current);
    ct_export(crs + v_offset(i), ct);
  }

  mpz_clear(current);
}

void prover(proof_t pi, uint8_t *crs, int ssp_fd, mpz_t witness, gamma_t gamma)
{
  nmod_poly_t t;
  nmod_poly_init(t, GAMMA_P);
  nmod_poly_t v_i;
  nmod_poly_init(v_i, GAMMA_P);
  nmod_poly_t v;
  nmod_poly_init(v, GAMMA_P);
  nmod_poly_t h;
  nmod_poly_init(h, GAMMA_P);

  uint8_t buf[8 * GAMMA_D];
  const size_t buflen = sizeof(buf);

  nmod_poly_t one;
  nmod_poly_init(one, GAMMA_P);
  nmod_poly_set_coeff_ui(one, 0, 1);

  // read t(x)
  read(ssp_fd, buf, buflen);
  nmod_poly_import(&t, buf, GAMMA_D);

  uint64_t delta = rand_modp();
  nmod_poly_set(v, t);
  nmod_poly_scalar_mul_nmod(v, v, delta);

  // assume l_u = 0
  read(ssp_fd, buf, buflen);
  nmod_poly_import(&v_i, buf, GAMMA_D);
  nmod_poly_add(v, v, v_i);

  for (size_t i = 0; i < GAMMA_M; i++) {
    read(ssp_fd, buf, buflen);
    if (mpz_tstbit(witness, i)) {
      nmod_poly_import(&v_i, buf, GAMMA_D);
      nmod_poly_add(v, v, v_i);
    }
  }

  nmod_poly_set(h, v);
  nmod_poly_pow(h, h, 2);
  nmod_poly_sub(h, h, one);
  nmod_poly_div(h, h, t);

  eval_poly(pi->h, gamma, crs+s_offset(0), h, GAMMA_D);
  eval_poly(pi->hat_h, gamma, crs+as_offset(0), h, GAMMA_D);
  eval_poly(pi->hat_v, gamma, crs+as_offset(0), v, GAMMA_D);

  nmod_poly_clear(h);
  nmod_poly_clear(v_i);
  nmod_poly_clear(v);
  nmod_poly_clear(h);
}

bool verifier(gamma_t gamma, int ssp_fd, vrs_t vrs, proof_t pi) {
  bool result = false;
  mpz_t h_s, hath_s, hatv_s, w_s, b_s, t_s, v_s;
  mpz_t test;
  mpz_inits(h_s, hath_s, hatv_s, w_s, b_s, t_s, v_s, NULL);
  mpz_init(test);

  uint8_t buf[8 * GAMMA_D];
  const size_t buflen = sizeof(buf);

  nmod_poly_t pp;
  nmod_poly_init(pp, GAMMA_P);
  /* t_s */
  read(ssp_fd, buf, buflen);
  nmod_poly_import(&pp, buf, GAMMA_D);
  mpz_set_ui(t_s, nmod_poly_evaluate_nmod(pp, vrs->s));

  /* v_s is just v0*/
  read(ssp_fd, buf, buflen);
  nmod_poly_import(&pp, buf, GAMMA_D);
  mpz_set_ui(v_s, nmod_poly_evaluate_nmod(pp, vrs->s));

  /* decrypt the proof */
  regev_decrypt(h_s, gamma, vrs->sk, pi->h);
  regev_decrypt(hath_s, gamma, vrs->sk, pi->hat_h);
  regev_decrypt(hatv_s, gamma, vrs->sk, pi->hat_v);
  regev_decrypt(w_s, gamma, vrs->sk, pi->v_w);
  regev_decrypt(b_s, gamma, vrs->sk, pi->b_w);

  /*  eq-pke  */
  mpz_mul_ui(test, h_s, vrs->alpha);
  mpz_sub(test, test, hath_s);
  mpz_mod(test, test, gamma.p);
  if (mpz_sgn(test)) goto end;

  mpz_mul_ui(test, v_s, vrs->alpha);
  mpz_sub(test, test, hatv_s);
  mpz_mod(test, test, gamma.p);
  if (mpz_sgn(test)) goto end;

  /* eq-lin */
  mpz_mul_ui(test, w_s, vrs->beta);
  mpz_sub(test, test, b_s);
  mpz_mod(test, test, gamma.p);
  if (mpz_sgn(test)) goto end;

  /* eq-div */
  mpz_mul(test, h_s, t_s);
  mpz_mul(v_s, v_s, v_s);
  mpz_sub(test, test, v_s);
  mpz_add_ui(test, test, 1);
  if (mpz_sgn(test)) goto end;

  result = true;

 end:
  mpz_clears(h_s, hath_s, hatv_s, w_s, b_s, t_s, v_s, NULL);
  mpz_clear(test);
  return result;
}
