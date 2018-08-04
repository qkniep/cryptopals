#include <openssl/evp.h>
#include <gmpxx.h>


int main(int argc, char** args) {
	if (argc != 2) {
		printf("Usage: %s <hex>\n", args[0]);
		exit(127);
	}

	mpz_class A;
	A.set_str(args[1], 16);
	size_t n;
	uint8_t* decoded = (uint8_t*) mpz_export(NULL, &n, 0, 1, 0, 0, A.get_mpz_t());

	uint8_t* encoded = (uint8_t*) malloc(n * 4);
	EVP_EncodeBlock(encoded, decoded, n);
	printf("%s\n", encoded); 

	free(decoded);
	free(encoded);
	return 0;
}
