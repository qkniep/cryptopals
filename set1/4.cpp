#include <iostream>
#include <string>
#include <gmpxx.h>


const int CHAR_SCORES[256] = {
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	14000,    2,  285,    0,   52,    2,    7,  204,   53,   54,   21,    0,  985,  252,  946,    8,
	  546,  461,  333,  188,  193,  374,  154,  120,  183,  282,   54,   37,    0,    0,    0,   12,
	    0,  281,  169,  229,  130,  138,  101,   93,  124,  223,   79,   47,  107,  259,  205,  106,
	  144,   12,  146,  305,  325,   57,   31,  107,    8,   94,    6,    0,    0,    0,    0,    0,
	    0, 5264,  866, 1960, 2370, 7742, 1297, 1207, 2956, 4527,   66,  461, 2553, 1467, 4536, 4729,
	 1256,   54, 4138, 4186, 5508, 1613,  653, 1016,  124, 1062,   66,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0
};


void printResults(uint8_t* buffer, const size_t &len, int lineNo, uint8_t key, uint64_t score) {
	printf("\nLineNo: %d  Key: %d  Score: %llu\n", lineNo, key, score);
	for (size_t i = 0; i < len; i++) {
		printf("%c", buffer[i] ^ key);
	}
	puts("");
}

void findBestScoringKey(uint8_t* buffer, const size_t &len, int lineNo, uint64_t &maxScore) {
	for (uint8_t c = 1; c != 0; c++) {  // try all characters as keys
		// calculate score
		uint64_t score = 0;
		for (size_t i = 0; i < len; i++) {
			score += CHAR_SCORES[buffer[i] ^ c];
		}

		if (score > maxScore) {
			maxScore = score;
			printResults(buffer, len, lineNo, c, score);
		}
	}
}

int main() {
	uint64_t maxScore = 0;
	int lineNo = 0;
	for (std::string line; std::getline(std::cin, line); lineNo++) {
		mpz_class A;
		A.set_str(line.c_str(), 16);
		size_t n;
		uint8_t* decoded = (uint8_t*) mpz_export(NULL, &n, 0, 1, 0, 0, A.get_mpz_t());

		findBestScoringKey(decoded, n, lineNo, maxScore);
	}
	return 0;
}
