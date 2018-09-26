check_PROGRAMS = test_lwe test_snark test_ssp test_aes
TESTS = $(check_PROGRAMS)

if AESNI
CFLAGS = -maes
else
LDADD = -lcrypto
endif


AES = aes.c aes.h
ENTROPY = entropy.c entropy.h $(AES)
LWE = lwe.c lwe.h
SNARK = snark.c snark.h
SSP = ssp.c ssp.h

bin_PROGRAMS = benchmark_lwe benchmark_eval benchmark_snark
test_lwe_SOURCES = test_lwe.c $(ENTROPY) $(LWE) tests.h
test_ssp_SOURCES = test_ssp.c $(ENTROPY) $(LWE) $(SSP) tests.h
test_snark_SOURCES = test_snark.c $(ENTROPY) $(LWE) $(SNARK) $(SSP) tests.h
test_aes_SOURCES = test_aes.c $(AES)
benchmark_lwe_SOURCES = benchmark_lwe.c $(ENTROPY) $(LWE) timeit.h
benchmark_eval_SOURCES = benchmark_eval.c $(ENTROPY) $(LWE) timeit.h
benchmark_snark_SOURCES = benchmark_snark.c $(ENTROPY) $(LWE) $(SNARK) $(SSP) timeit.h
