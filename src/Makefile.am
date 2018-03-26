check_PROGRAMS = test_lwe test_snark

LWE = lwe.c lwe.h
SNARK = snark.c snark.h
TESTS = $(check_PROGRAMS)

bin_PROGRAMS = benchmark_lwe
test_lwe_SOURCES = test_lwe.c $(LWE)
test_snark_SOURCES = test_snark.c $(LWE) $(SNARK)
benchmark_lwe_SOURCES = benchmark_lwe.c $(LWE)
#group_bench_LDADD = -lcrypto -lssl
