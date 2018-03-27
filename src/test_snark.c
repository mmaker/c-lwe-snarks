#include <assert.h>
#include <stdlib.h>

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


  decrypt(got, gamma, vk->sk, crs->alpha_s[0]);
  assert(!mpz_cmp(got, vk->alpha));
  for (size_t i = 0; i < gamma.d; i++) {
    mpz_mul_mod(s_i, s_i, vk->s, gamma.p);
    decrypt(got, gamma, vk->sk, crs->s[i]);
    assert(!mpz_cmp(got, s_i));

    mpz_mul_mod(alpha_s_i, vk->alpha, s_i, gamma.p);
    decrypt(got, gamma, vk->sk, crs->alpha_s[i+1]);
    assert(!mpz_cmp(got, alpha_s_i));
  }

  crs_clear(crs, gamma);
}


int main() {
  test_crs();
  return EXIT_SUCCESS;
}
