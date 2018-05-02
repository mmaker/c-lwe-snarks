#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "lwe.h"
#include "snark.h"
#include "ssp.h"


void crs_gen(crs_t crs, vk_t vk, gamma_t gamma, int ssp_fd) {
  mpz_t alpha, beta, s, s_i, t_i, alpha_s_i;
  mpz_inits(alpha, beta, s, s_i, t_i, alpha_s_i, NULL);
  ctx_t ct;
  ct_init(ct, gamma);

  mpz_urandomm(s, gamma.rstate, gamma.p);
  mpz_urandomm(alpha, gamma.rstate, gamma.p);
  mpz_urandomm(beta, gamma.rstate, gamma.p);

  // XXX some of these can be removed.
  key_gen(vk->sk, gamma);
  mpz_inits(vk->s, vk->alpha, vk->beta, NULL);
  mpz_set(vk->s, s);
  mpz_set(vk->alpha, alpha);
  mpz_set(vk->beta, beta);

  // create a new PRG that will be used to reproduce encryptions
  gmp_randstate_t rs;
  gmp_randinit_default(rs);
  rseed_t rseed;
  getrandom(&rseed, sizeof(rseed_t), GRND_NONBLOCK);
  mpz_t mpz_rseed;
  mpz_init(mpz_rseed);
  mpz_import(mpz_rseed, 32, 1, sizeof(rseed[0]), 0, 0, rseed);
  gmp_randseed(rs, mpz_rseed);
  mpz_clear(mpz_rseed);

  /* α s^0 */
  mpz_set_ui(s_i, 1);
  mpz_mul_mod(alpha_s_i, s_i, alpha, gamma.p);
  mpz_init(crs->alpha_s[0]);
  encrypt(ct, gamma, rs, vk->sk, alpha_s_i);
  mpz_set(crs->alpha_s[0], ct->b);

  /* initialize β t (s) */
  poly_t tt;
  mpz_initv(tt, GAMMA_D + 1);
  read_polynomial(ssp_fd, tt, 0);
  mpz_init_set(crs->beta_t, tt[0]);
  for (size_t i = 0; i < gamma.d; i++) {
    /* s^i  */
    mpz_init(crs->s[i]);
    mpz_mul_mod(s_i, s_i, s, gamma.p);
    encrypt(ct, gamma, rs, vk->sk, s_i);
    mpz_set(crs->s[i], ct->b);

    /* α s^i */
    mpz_init(crs->alpha_s[i+1]);
    mpz_mul_mod(alpha_s_i, s_i, alpha, gamma.p);
    // XXX: change the error
    encrypt(ct, gamma, rs, vk->sk, alpha_s_i);
    mpz_set(crs->alpha_s[i+1], ct->b);

    /* β t(s) - generate t(s) */
    mpz_addmul(crs->beta_t, tt[i+1], s_i);
  }

  /* β t(s) */
  mpz_mul_mod(crs->beta_t, crs->beta_t, beta, gamma.p);

  memmove(crs->rseed, rseed, sizeof(rseed_t));

  mpz_clears(alpha, beta, s, s_i, alpha_s_i, NULL);
  ct_clear(ct, gamma);
}


void prover(proof_t proof, crs_t crs, mpz_t witness[]);
bool verifier(gamma_t gamma, int ssp_fd, vk_t vk, proof_t proof) {
  bool result = false;
  mpz_t h_s, hath_s, hatv_s, w_s, b_s, t_s, v_s;
  mpz_t test;
  mpz_inits(h_s, hath_s, hatv_s, w_s, b_s, t_s, v_s, NULL);
  mpz_init(test);

  poly_t pp;
  /* t_s */
  poly_init(pp);
  read_polynomial(ssp_fd, pp, T);
  evaluate_polynomial(t_s, pp, vk->s, gamma.p);

  /* v_s */
  read_polynomial(ssp_fd, pp, V(0));
  // XXX this is not correct
  evaluate_polynomial(v_s, pp, vk->s, gamma.p);
  mpz_add(v_s, v_s, w_s);

  poly_clear(pp);

  /* decrypt the proof */
  decrypt(h_s, gamma, vk->sk, &proof[0]);
  decrypt(hath_s, gamma, vk->sk, &proof[1]);
  decrypt(hatv_s, gamma, vk->sk, &proof[2]);
  decrypt(w_s, gamma, vk->sk, &proof[3]);
  decrypt(b_s, gamma, vk->sk, &proof[4]);

  /*  eq-pke  */
  mpz_mul(test, vk->alpha, h_s);
  mpz_sub(test, test, hath_s);
  mpz_mod(test, test, gamma.p);
  if (mpz_sgn(test)) goto end;

  mpz_mul(test, vk->alpha, v_s);
  mpz_sub(test, test, hatv_s);
  mpz_mod(test, test, gamma.p);
  if (mpz_sgn(test)) goto end;

  /* eq-lin */
  mpz_mul(test, vk->beta, w_s);
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

void vk_clear(vk_t vk, gamma_t gamma)
{
  mpz_clear(vk->s);
  mpz_clear(vk->alpha);
  key_clear(vk->sk, gamma);
}

void crs_clear(crs_t crs, gamma_t gamma)
{
  mpz_clearv(crs->s, gamma.d);
  mpz_clearv(crs->alpha_s, gamma.d + 1);
}
