#include <gmpxx.h>

const char INPUT[75] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
const char KEY[4] = "ICE";


int main() {
	for (size_t i = 0; i < strlen(INPUT); i++) {
		printf("%02x", INPUT[i] ^ KEY[i % (strlen(KEY) + 1)]);
	}
	puts("");
	return 0;
}
