#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "snark.h"


void test_crs()
{
  crs_t crs;
  vk_t vk;
  gamma_t gamma = param_gen();
  crs_gen(crs, vk, gamma);

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


int main() {
  test_crs();
  return EXIT_SUCCESS;
}
