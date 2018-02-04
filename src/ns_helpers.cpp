#include <stdexcept>
#include <string>

#include <selfup/ns_helpers.h>

char decode_hex_char(const char hex_char)
{
	/* '0' to '9' guaranteed contiguous */

	if (hex_char >= '0' && hex_char <= '9')
		return hex_char - '0';

	/* the letters are contiguous in ASCII but no standard */

	switch (hex_char) {
	case 'a':
	case 'A':
		return 10;
	case 'b':
	case 'B':
		return 11;
	case 'c':
	case 'C':
		return 12;
	case 'd':
	case 'D':
		return 13;
	case 'e':
	case 'E':
		return 14;
	case 'f':
	case 'F':
		return 15;
	default:
		throw std::runtime_error("decode hex char");
	}

	return 0;
}

std::string decode_hex(const std::string &hex, bool web_programmer_designed_swapped_hex_mental_illness)
{
	std::string bin(hex.size() / 2, '\0');

	/* one full byte is a hex pair of characters - better be divisible by two */

	if (hex.size() % 2 != 0)
		throw std::runtime_error("hex divisibility");

	/* decode */

	for (size_t i = 0; i < hex.size(); i += 2) {
		char first = decode_hex_char(hex[i]) & 0xF;
		char second = decode_hex_char(hex[i + 1]) & 0xF;
		if (web_programmer_designed_swapped_hex_mental_illness)
			bin[i / 2] = first << 4 | second << 0;
		else
			bin[i / 2] = first << 0 | second << 4;
	}

	return bin;
}

std::string encode_hex(const std::string &bin, bool web_programmer_designed_swapped_hex_mental_illness)
{
	std::string hex;
	/* lowercase hex */
	const char chars[] = "0123456789abcdef";
	for (size_t i = 0; i < bin.size(); i++) {
		char first = chars[(bin[i] >> 0) & 0xF];
		char second = chars[(bin[i] >> 4) & 0xF];
		if (web_programmer_designed_swapped_hex_mental_illness) {
			hex.append(1, second);
			hex.append(1, first);
		}
		else {
			hex.append(1, first);
			hex.append(1, second);
		}
	}
	return hex;
}
