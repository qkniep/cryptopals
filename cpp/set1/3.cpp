#include <gmpxx.h>

#include "xorCipher.h"


int main(int argc, char** args) {
	if (argc != 2) {
		printf("Usage: %s <hex>\n", args[0]);
		exit(127);
	}

	mpz_class A;
	A.set_str(args[1], 16);
	size_t n;
	uint8_t* decoded = (uint8_t*) mpz_export(NULL, &n, 0, 1, 0, 0, A.get_mpz_t());

	uint64_t maxScore = 0;
	findBestScoringKey(decoded, n, maxScore);
	return 0;
}
