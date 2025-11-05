#include <gmpxx.h>


int main(int argc, char** args) {
	if (argc != 3) {
		printf("Usage: %s <hex1> <hex2>\n", args[0]);
		exit(127);
	} else if (strlen(args[1]) != strlen(args[2])) {
		printf("Error: input strings must have same length\n");
		exit(1);
	}

	mpz_class A, B;
	A.set_str(args[1], 16);
	B.set_str(args[2], 16);

	size_t nA, nB;
	uint8_t* bytesA = (uint8_t*) mpz_export(NULL, &nA, 0, 1, 0, 0, A.get_mpz_t());
	uint8_t* bytesB = (uint8_t*) mpz_export(NULL, &nB, 0, 1, 0, 0, B.get_mpz_t());

	for (size_t i = 0; i < nA; i++) {  // assuming nA == nB
		printf("%02x", bytesA[i] ^ bytesB[i]);
	}
	puts("");
	return 0;
}
