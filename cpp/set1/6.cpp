#include <iostream>
#include <string>
#include <openssl/evp.h>

#include "xorCipher.h"

#define MIN_KEYSIZE 2
#define MAX_KEYSIZE 40
#define HAMMING_TRIALS 8


int editDistance(uint8_t* buffer, int pos, int len) {
	int ed = 0;
	for (int i = pos; i < pos + len; i++) {
		uint8_t x = buffer[i] ^ buffer[len+i];
		while (x != 0) {  // count number of 1 bits in x (=ED of XOR'd bytes)
			x = x & (x-1);
			ed++;
		}
	}
	return ed;
}

int averageEditDistance(uint8_t* buffer, int len) {
	int sum = 0;
	for (int i = 0; i < HAMMING_TRIALS; i++) {
		sum += editDistance(buffer, 2*i*len, len);
	}
	return sum / HAMMING_TRIALS;
}

int findKeyLength(uint8_t* buffer) {
	float minNormED = 999999.f;
	int guessedKeyLength = 0;
	for (int keyLength = MIN_KEYSIZE; keyLength < MAX_KEYSIZE; keyLength++) {
		float normED = (float) averageEditDistance(buffer, keyLength) / keyLength;
		if (normED < minNormED) {
			minNormED = normED;
			printf("kl: %d, ned: %f\n", keyLength, normED);
			guessedKeyLength = keyLength;
		}
	}
	return guessedKeyLength;
}

int main() {
	std::string input = "";
	//uint8_t* decoded = NULL;
	uint8_t decoded[65536];

	for (std::string line; std::getline(std::cin, line); ) {
		input += line;
	}

	size_t n = EVP_DecodeBlock(decoded, (uint8_t*) input.c_str(), input.length());
	int keyLength = findKeyLength(decoded);
	printf("The (most likely) correct key length is: %d\n", keyLength);

	const size_t blockSize = n / keyLength;
	std::string key = "";
	for (int i = 0; i < keyLength; i++) {
		uint8_t block[32768] = {0};
		for (int j = 0; j < blockSize; j++) {
			block[j] = decoded[keyLength * j + i];
		}

		uint64_t maxScore = 0;
		key += (char) findBestScoringKey(block, blockSize, maxScore);
	}

	printf("KEY: %s\n", key.c_str());
	return 0;
}
