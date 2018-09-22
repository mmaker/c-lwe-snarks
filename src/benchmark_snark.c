#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <gmp.h>
#include <flint/nmod_poly.h>

#include "lwe.h"
#include "snark.h"
#include "ssp.h"
#include "timeit.h"



#define CRS_FILENAME "/home/maker/crs"
#define SSP_FILENAME "/home/maker/ssp"

#include <assert.h>
bool benchmark_snark()
{
  rng_t rng;
  RNG_INIT(rng);
  INIT_TIMEIT();

  // SSP GENERATION
  int sspfd = open(SSP_FILENAME, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
  ftruncate(sspfd, SSP_SIZE);
  uint8_t *ssp = mmap(NULL, SSP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, sspfd, 0);
  mpz_t witness;
  mpz_init(witness);
  random_ssp(witness, ssp, rng);
  msync(ssp, SSP_SIZE, MS_SYNC);
  munmap(ssp, SSP_SIZE);
  close(sspfd);
  perror("SSP generation");

  // CRS GENERATION
  int crsfd = open(CRS_FILENAME, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
  ftruncate(crsfd, CRS_SIZE);
  uint8_t *crs = mmap(NULL, CRS_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, crsfd, 0);
  sspfd = open(SSP_FILENAME, O_RDONLY | O_LARGEFILE);
  ssp = mmap(NULL, SSP_SIZE, PROT_READ, MAP_PRIVATE, sspfd, 0);

  vrs_t vrs;
  START_TIMEIT();
  setup(crs, vrs, ssp, rng);
  END_TIMEIT();
  msync(crs, CRS_SIZE, MS_SYNC);
  munmap(crs, CRS_SIZE);
  close(crsfd);
  perror("CRS generation");
  printf("setup\t" TIMEIT_FORMAT "\n", GET_TIMEIT());

  // PROVER
  proof_t pi;
  proof_init(pi);
  crsfd = open(CRS_FILENAME, O_RDONLY | O_LARGEFILE);
  crs = mmap(NULL, CRS_SIZE, PROT_READ, MAP_PRIVATE, crsfd, 0);
  START_TIMEIT();
  prover(pi, crs, ssp, witness, rng);
  END_TIMEIT();
  perror("Prover");
  printf("prover\t" TIMEIT_FORMAT "\n", GET_TIMEIT());


  // VERIFIER
  START_TIMEIT();
  bool out = verifier(ssp, vrs, pi);
  END_TIMEIT();
  perror("Verifier");
  printf("verifier\t" TIMEIT_FORMAT "\n", GET_TIMEIT());

  proof_clear(pi);
  munmap(crs, CRS_SIZE);
  munmap(ssp, SSP_SIZE);
  close(crsfd);
  close(sspfd);

  return out;
}


int main() {
  exit(benchmark_snark() ? EXIT_SUCCESS : EXIT_FAILURE);
}
