check_PROGRAMS = test_lwe test_snark test_ssp test_aes
TESTS = $(check_PROGRAMS)

if AES_NI
LDADD = -lcrypto
else
AM_CFLAGS = $(CFLAGS) -maes
endif

AES = aes.c aes.h
LWE = lwe.c lwe.h
SNARK = snark.c snark.h
SSP = ssp.c ssp.h

bin_PROGRAMS = benchmark_lwe benchmark_eval benchmark_snark
test_lwe_SOURCES = test_lwe.c $(LWE) tests.h
test_ssp_SOURCES = test_ssp.c $(LWE) $(SSP) tests.h
test_snark_SOURCES = test_snark.c $(LWE) $(SNARK) $(SSP) tests.h
test_aes_SOURCES = test_aes.c $(AES)
benchmark_lwe_SOURCES = benchmark_lwe.c $(LWE) timeit.h
benchmark_eval_SOURCES = benchmark_eval.c $(LWE) timeit.h
benchmark_snark_SOURCES = benchmark_snark.c $(LWE) $(SNARK) $(SSP) timeit.h
