//
//  main.cpp
//  CryptoChallenge
//
//  Created by Gabriel Aubut-Lussier on 2015-09-16.
//  Copyright (c) 2015 Gabriel Aubut-Lussier. All rights reserved.
//

#include <iostream>
#include <string>

using size_t = std::string::size_type;

// Here is a piece of code I have produced to solve a crypto challenge. In this challenge, I was
// provided with an encrypted string of characters which I needed to decrypt. I was also provided
// with a web service through which I could encrypt data. I had to encrypt many messages in order
// to understand how the encryption was being done. Then, with this understanding, all that is left
// is to write a decryption engine to decrypt the challenge.
//
// Let's assume this decrypting algorithm is a performance critical piece of code for an organization.
// It runs against thousands of requests per second on some servers and it needs to perform as best as it
// can. This sample piece of code optimizes the conditionnal statement out of the performance critical
// loop and relies on a templated function to avoid writing the decryption logic twice : once to decrypt
// blocks of 3 characters and once to decrypt the last block of every message (which holds 1, 2 or 3
// characters).
template<int N>
void decryptBlock(size_t c1, size_t c2, size_t c3, size_t c4, size_t& transposition);

// This specialization decrypts a single character and ignores the two useless bytes.
template<>
void decryptBlock<2>(size_t crypted1, size_t crypted2, size_t crypted3, size_t crypted4, size_t& transposition)
{
	size_t decrypted = (crypted1 << 2) | (crypted2 >> 4);
	decrypted -= transposition;
	decrypted &= 0x7F;
	std::cout << char(decrypted);
	++transposition;
}

// This specialization decrypts two characters and ignores the single useless byte.
template<>
void decryptBlock<3>(size_t crypted1, size_t crypted2, size_t crypted3, size_t crypted4, size_t& transposition)
{
	decryptBlock<2>(crypted1, crypted2, crypted3, crypted4, transposition);
	size_t decrypted = ((crypted2 & 0xF) << 4) | (crypted3 >> 2);
	decrypted -= transposition;
	decrypted &= 0x7F;
	std::cout << char(decrypted);
	++transposition;
}

// This specialization decrypts three characters.
template<>
void decryptBlock<4>(size_t crypted1, size_t crypted2, size_t crypted3, size_t crypted4, size_t& transposition)
{
	decryptBlock<3>(crypted1, crypted2, crypted3, crypted4, transposition);
	size_t decrypted = ((crypted3 & 0x3) << 6) | crypted4;
	decrypted -= transposition;
	decrypted &= 0x7F;
	std::cout << char(decrypted);
	++transposition;
}

// Each encrypted byte holds 6 bits of meaningful data that is retrieved by looking up the index
// of the character in the base64 representation.
static std::string base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
size_t indexOfChar(char c)
{
	return base64.find(c);
}

// Unpacks 4 bytes of encrypted contents out of the string and extracts the 6 bits of meaningful
// data for each of them.
void getCryptedBytes(const std::string& str, size_t offset, std::tuple<size_t&, size_t&, size_t&, size_t&> destination)
{
	std::get<0>(destination) = indexOfChar(str[offset++]);
	std::get<1>(destination) = indexOfChar(str[offset++]);
	std::get<2>(destination) = indexOfChar(str[offset++]);
	std::get<3>(destination) = indexOfChar(str[offset++]);
}

void decrypt(const std::string& str)
{
	const size_t cryptedBlockSize = 4;
	size_t numberOfBlocks = str.length() / cryptedBlockSize; // Number of blocks of encrypted
	size_t numberOfCompleteBlocks = numberOfBlocks - 1;
	size_t offsetLastBlock = numberOfCompleteBlocks * cryptedBlockSize;
	
	// Computation of the number of useless bytes in the last encrypted block
	std::string::const_iterator it = str.begin() + offsetLastBlock + 2;
	auto uselessBytesInLastBlock = std::count_if(it, str.cend(), [](char caractere) -> bool {
		return caractere == '=';
	});
	
	size_t transposition = 79; // Arbitrary initial transposition offset for the decryption algorithm
	
	size_t c1, c2, c3, c4;
	// Decryption of N - 1 blocks of encrypted data
	// This is the performance critical loop where the algorithmic complexity has the biggest impact
	for (size_t i = 0, n = numberOfCompleteBlocks; i < n; ++i) {
		getCryptedBytes(str, i * cryptedBlockSize, std::tie(c1, c2, c3, c4));
		decryptBlock<4>(c1, c2, c3, c4, transposition);
	}
	
	// Decryption of the last block of encrypted data
	// This block might hold 1, 2 or 3 characters.
	getCryptedBytes(str, numberOfCompleteBlocks * cryptedBlockSize, std::tie(c1, c2, c3, c4));
	switch (uselessBytesInLastBlock) {
		case 0: {
			decryptBlock<4>(c1, c2, c3, c4, transposition);
			break;
		}
		case 1: {
			decryptBlock<3>(c1, c2, c3, c4, transposition);
			break;
		}
		case 2: {
			decryptBlock<2>(c1, c2, c3, c4, transposition);
			break;
		}
		default: {
			break;
		}
	}
	
	std::cout << std::endl;
}

int main(int argc, const char * argv[])
{
	// This is the original string to decrypt
	// It is not dynamic and thus this program assumes the input is valid Base64.
	std::string str = "lsK2s8d0v8W5eXmuw8F9y8TT1MPKyYXP2qKJjLTSjbeP59Lg59nZltiY8Nvt6Z3k9Pr7+6Pq6uvz8ffxt6zWtfOw8gAH/fYCAPkMuggVvQURAREKDAcYx8nI/AsfIR8SECnRGybUFtYeJyge2yAeN980MOI2MzE8LOg5P0VGOTNC/g==";
	std::string str2 = "ebwN";
	
	// Small optimization to remove unnecessary synchronisation with C's io functions that won't be used in this program
	std::cout.sync_with_stdio(false);
	
	decrypt(str);
	decrypt(str2);
}
