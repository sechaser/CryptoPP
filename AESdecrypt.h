#ifndef AESDECRYPT
#define AESDECRYPT

#include <string>

#include "aes.h"

void AES_ECBdecrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], std::string& ciphertext, std::string& dectext);

void AES_CBCdecrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                          std::string& ciphertext, std::string& dectext);

void AES_CFBdecrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                          std::string& ciphertext, std::string& dectext);

void AES_OFBdecrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                    std::string& ciphertext, std::string& dectext);
#endif // AESDECRYPT

