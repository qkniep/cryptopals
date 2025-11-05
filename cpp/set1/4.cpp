#include <iostream>
#include <string>
#include <gmpxx.h>

#include "xorCipher.h"


int main() {
	uint64_t maxScore = 0;
	int lineNo = 0;
	for (std::string line; std::getline(std::cin, line); lineNo++) {
		mpz_class A;
		A.set_str(line.c_str(), 16);
		size_t n;
		uint8_t* decoded = (uint8_t*) mpz_export(NULL, &n, 0, 1, 0, 0, A.get_mpz_t());

		findBestScoringKey(decoded, n, maxScore);
	}
	return 0;
}
