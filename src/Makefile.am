check_PROGRAMS = test_lwe test_snark test_ssp
TESTS = $(check_PROGRAMS)

LWE = lwe.c lwe.h
SNARK = snark.c snark.h
SSP = ssp.c ssp.h

bin_PROGRAMS = benchmark_lwe
test_lwe_SOURCES = test_lwe.c $(LWE)
test_ssp_SOURCES = test_ssp.c $(LWE) $(SSP)
test_snark_SOURCES = test_snark.c $(LWE) $(SNARK) $(SSP)
benchmark_lwe_SOURCES = benchmark_lwe.c $(LWE)
