#ifndef AESENCRYPT
#define AESENCRYPT

#include <string>

#include "aes.h"

void AES_ECBencrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], std::string& plaintext, std::string& ciphertext);

void AES_CBCencrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext);

void AES_CFBencrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext);

void AES_OFBencrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext);
#endif // AESENCRYPT

