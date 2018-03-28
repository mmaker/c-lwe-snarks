#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "ssp.h"

void test_read_write()
{
  int fds[2];
  pipe2(fds, O_NONBLOCK);

  poly_t pp;
  mpz_initv(pp, GAMMA_D);

  write_ssp(fds[1]);
  read_polynomial(fds[0], pp, 0);

  assert(1);
  mpz_clearv(pp, GAMMA_D);
}

int main()
{
  test_read_write();
}
