#include <iostream>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>


int main() {
	int len, c_len, p_len;
	std::string input;
	uint8_t ciphertext[65536];
	uint8_t plaintext[65536];
	const uint8_t* key = (uint8_t*) "YELLOW SUBMARINE";

	for (std::string line; std::getline(std::cin, line); ) {
		input += line;
	}

	// decode Base64
	c_len = EVP_DecodeBlock(ciphertext, (uint8_t*) input.c_str(), input.length());

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, c_len);
	p_len = len;
	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	p_len += len;

	plaintext[p_len] = '\0';
	printf("The decrypted message is: %s\n", plaintext);

	return 0;
}
