#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/random.h>
#include <sys/syscall.h>

#include <gmp.h>

#include "lwe.h"

void test_eval();


int main()
{
  // test_correctness();
  test_eval();
  return EXIT_SUCCESS;
}
