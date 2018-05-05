#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <flint/nmod_poly.h>

#include "ssp.h"

void test_import_export()
{
  nmod_poly_t p, q;
  nmod_poly_init(p, 0xfffffffb);
  nmod_poly_init(q, 0xfffffffb);

  nmod_poly_set_coeff_ui(p, 0, 2);
  nmod_poly_set_coeff_ui(p, 1, 1);
  nmod_poly_set_coeff_ui(p, 2, 3);

  uint64_t buf[3];
  nmod_poly_export(buf, &p);
  nmod_poly_import(&p, buf, 2);

  nmod_poly_sub(p, p, q);
  assert(nmod_poly_degree(q) == -1);
}

int main()
{
  test_import_export();
}
