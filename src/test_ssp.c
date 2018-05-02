#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ssp.h"

void test_read_write()
{
  int fds[2];
  pipe(fds);

  if (!fork()) {
    write_ssp(fds[1]);
  } else {
    poly_t pp;

    poly_init(pp);
    read_polynomial(fds[0], pp, 0);

    gmp_printf("%Zd\n", pp[0]);
    mpz_clearv(pp, GAMMA_D);
 }
}

int main()
{
  test_read_write();
}
