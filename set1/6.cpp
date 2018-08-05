#include <iostream>
#include <string>
#include <openssl/evp.h>

#include "xorCipher.h"

#define MIN_KEYSIZE 2
#define MAX_KEYSIZE 40


int editDistance(uint8_t* buffer, int len) {
	int ed = 0;
	for (int i = 0; i < len; i++) {
		uint8_t x = buffer[i] ^ buffer[len+i];
		while (x != 0) {  // count number of 1 bits in x (=ED of XOR'd bytes)
			x = x & (x-1);
			ed++;
		}
	}
	return ed;
}

int findKeyLength(uint8_t* buffer) {
	float minNormED = 999999.f;
	int guessedKeyLength = 0;
	for (int keyLength = MIN_KEYSIZE; keyLength < MAX_KEYSIZE; keyLength++) {
		float normED = (float) editDistance(buffer, keyLength) / keyLength;
		if (normED < minNormED) {
			minNormED = normED;
			printf("kl: %d, ned: %f\n", keyLength, normED);
			guessedKeyLength = keyLength;
		}
	}
	return guessedKeyLength;
}

int main() {
	uint64_t maxScore = 0;
	int lineNo = 0;
	std::string input = "";
	//uint8_t* decoded = NULL;
	uint8_t decoded[65536];

	for (std::string line; std::getline(std::cin, line); lineNo++) {
		input += line;
	}

	size_t n = EVP_DecodeBlock(decoded, (uint8_t*) input.c_str(), input.length());
	int keyLength = findKeyLength(decoded);
	printf("The (most likely) correct key length is: %d\n", keyLength);
	findBestScoringKey(decoded, n, maxScore);
	return 0;
}
