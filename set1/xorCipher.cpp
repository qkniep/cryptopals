#include <iostream>

#include "xorCipher.h"


void printResults(uint8_t* buffer, const size_t &len, uint8_t key, uint64_t score) {
	printf("\nKey: %d  Score: %llu\n", key, score);
	for (size_t i = 0; i < len; i++) {
		printf("%c", buffer[i] ^ key);
	}
	puts("");
}

uint8_t findBestScoringKey(uint8_t* buffer, const size_t &len, uint64_t &maxScore) {
	uint8_t bestKey = 0;
	for (uint8_t k = 1; k != 0; k++) {  // try all characters as keys
		// calculate score
		uint64_t score = 0;
		for (size_t i = 0; i < len; i++) {
			score += CHAR_SCORES[buffer[i] ^ k];
		}

		if (score > maxScore) {
			maxScore = score;
			bestKey = k;
			printResults(buffer, len, k, score);
		}
	}
	return bestKey;
}
