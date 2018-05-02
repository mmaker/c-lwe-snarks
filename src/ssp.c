#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <gmp.h>

#include "lwe.h"
#include "ssp.h"

#define GAMMA_P_BYTES (32 / 8)
#define GAMMA_M (1<<15 * 3 / 4)

void write_ssp(int fd)
{
  gamma_t gamma = param_gen();
  sk_t sk;
  key_gen(sk, gamma);

  mpz_t a;
  uint8_t out[GAMMA_P_BYTES] = {0};

  for (size_t m = 0; m < GAMMA_M+1; m++) {
    for (size_t i = 0; i < GAMMA_D+1; i++) {
      mpz_urandomm(a, gamma.rstate, gamma.p);
      mpz_export(out, NULL, 1, sizeof(uint8_t), 0, 0, a);

      //if (m == 1 && i == 0) gmp_printf("%Zd\n", a);
      write(fd, out, GAMMA_P_BYTES);
    }
  }

  key_clear(sk, gamma);
  param_clear(&gamma);
}


void read_polynomial(int fd, poly_t pp, uint32_t i)
{
  uint8_t repr[GAMMA_P_BYTES];

  const off_t offset = i * GAMMA_P_BYTES * (GAMMA_D+1);
  lseek(fd, offset, SEEK_SET);
  read(fd, repr, GAMMA_P_BYTES);

  for (size_t i = 0; i < (GAMMA_D+1); i++) {
    mpz_import(pp[i], GAMMA_P_BYTES, 1, sizeof(uint8_t), 0, 0, repr);
  }
}


void evaluate_polynomial(mpz_t rop, poly_t t, mpz_t x, mpz_t modulus) {
  mpz_t x_i;
  mpz_set(rop, t[0]);
  mpz_init_set(x_i, x);
  for (size_t i = 1; i < GAMMA_D+1; i++) {
    mpz_addmul(rop, t[i], x_i);
    mpz_mul(x_i, x_i, x);
  }
  mpz_mod(rop, rop, modulus);
  mpz_clear(x_i);
}


bool mpz_eqv(mpz_t a[], mpz_t b[], size_t len)
{
  if (len == 0) return false;
  else return (!mpz_cmp(a[0] , b[0]) &&
               mpz_eqv(a+1, b+1, len-1));
}

int foo()
{
  //write_ssp(1);

  poly_t pp;
  mpz_initv(pp, GAMMA_D);
  read_polynomial(0, pp, 1);
  mpz_clearv(pp, GAMMA_D);

  return EXIT_SUCCESS;
}
