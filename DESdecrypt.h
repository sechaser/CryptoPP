#ifndef DECDECRYPT
#define DECDECRYPT

#include <string>

#include "des.h"

void DES_ECBdecrypt(byte (&key)[CryptoPP::DES::DEFAULT_KEYLENGTH], std::string& ciphertext, std::string& dectext);

void DES_CBCdecrypt(byte (&key)[CryptoPP::DES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::DES::BLOCKSIZE],
                          std::string& ciphertext, std::string& dectext);

void DES_CFBdecrypt(byte (&key)[CryptoPP::DES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::DES::BLOCKSIZE],
                          std::string& ciphertext, std::string& dectext);

void DES_OFBdecrypt(byte (&key)[CryptoPP::DES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::DES::BLOCKSIZE],
                    std::string& ciphertext, std::string& dectext);

#endif // DECDECRYPT

