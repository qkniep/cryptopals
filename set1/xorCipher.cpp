#include <iostream>

#include "xorCipher.h"


void printResults(uint8_t* buffer, const size_t &len, uint8_t key, uint64_t score) {
	printf("\nKey: %d  Score: %llu\n", key, score);
	for (size_t i = 0; i < len; i++) {
		printf("%c", buffer[i] ^ key);
	}
	puts("");
}

void findBestScoringKey(uint8_t* buffer, const size_t &len, uint64_t &maxScore) {
	for (uint8_t c = 1; c != 0; c++) {  // try all characters as keys
		// calculate score
		uint64_t score = 0;
		for (size_t i = 0; i < len; i++) {
			score += CHAR_SCORES[buffer[i] ^ c];
		}

		if (score > maxScore) {
			maxScore = score;
			printResults(buffer, len, c, score);
		}
	}
}
