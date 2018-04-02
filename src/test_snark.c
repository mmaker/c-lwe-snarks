#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "snark.h"


void test_crs()
{
  crs_t crs;
  vk_t vk;
  gamma_t gamma = param_gen();
  crs_gen(crs, vk, gamma, 0);

  mpz_t s_i, alpha_s_i, got;
  mpz_init_set_ui(s_i, 1);
  mpz_init(alpha_s_i);
  mpz_init(got);

  gamma_t gamma_ = param_gen_from_seed(crs->rseed);
  ctx_t ct;
  ct_init(ct, gamma_);

  assert(!memcmp(crs->rseed, gamma_.rseed, sizeof(rseed_t)));

  decompress_encryption(ct, gamma_, gamma_.rstate, crs->alpha_s[0]);
  decrypt(got, gamma_, vk->sk, ct);
  assert(!mpz_cmp(got, vk->alpha));

  for (size_t i = 0; i < gamma.d; i++) {
    mpz_mul_mod(s_i, s_i, vk->s, gamma.p);
    decompress_encryption(ct, gamma_, gamma_.rstate, crs->s[i]);
    decrypt(got, gamma_, vk->sk, ct);
    assert(!mpz_cmp(got, s_i));

    mpz_mul_mod(alpha_s_i, vk->alpha, s_i, gamma.p);
    decompress_encryption(ct, gamma_, gamma_.rstate, crs->alpha_s[i+1]);
    decrypt(got, gamma_, vk->sk, ct);
    assert(!mpz_cmp(got, alpha_s_i));
  }

  mpz_clears(s_i, alpha_s_i, got, NULL);
  crs_clear(crs, gamma);
  vk_clear(vk, gamma);
  param_clear(&gamma);
  param_clear(&gamma_);
  ct_clear(ct, gamma);
}

void test_verifier()
{
  crs_t crs;
  vk_t vk;
  gamma_t gamma = param_gen();
  crs_gen(crs, vk, gamma, 0);

  proof_t proof;
  for (size_t i = 0; i < 5; i++) {
    ct_init(&proof[i], gamma);
  }


  mpz_t h_s, hath_s, hatv_s, w_s, b_s;
  mpz_inits(h_s, hath_s, hatv_s, w_s, b_s, NULL);
  mpz_urandomm(h_s, gamma.rstate, gamma.p);
  mpz_urandomm(w_s, gamma.rstate, gamma.p);
  mpz_mul_mod(hath_s, h_s, vk->alpha, gamma.p);
  mpz_mul_mod(b_s, w_s, vk->beta, gamma.p);

  encrypt(&proof[0], gamma, gamma.rstate, vk->sk, h_s);
  encrypt(&proof[1], gamma, gamma.rstate, vk->sk, hath_s);
  encrypt(&proof[3], gamma, gamma.rstate, vk->sk, w_s);
  encrypt(&proof[4], gamma, gamma.rstate, vk->sk, b_s);

  assert(verifier(gamma, vk, proof));


  mpz_clears(h_s, hath_s, hatv_s, w_s, b_s, NULL);
  for (size_t i = 0; i < 5; i++) {
    ct_clear(&proof[i], gamma);
  }
  param_clear(&gamma);
  vk_clear(vk, gamma);
  crs_clear(crs, gamma);
}


int main() {
  test_crs();
  test_verifier();
  return EXIT_SUCCESS;
}
