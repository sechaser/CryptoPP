#include "DESencrypt.h"

#include "modes.h"
#include "filters.h"

void DES_ECBencrypt(byte (&key)[CryptoPP::DES::DEFAULT_KEYLENGTH], std::string& plaintext, std::string& ciphertext)
{

}

void DES_CBCencrypt(byte (&key)[CryptoPP::DES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::DES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext)
{

}

void DES_CFBencrypt(byte (&key)[CryptoPP::DES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::DES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext)
{

}

void DES_OFBencrypt(byte (&key)[CryptoPP::DES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::DES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext)
{

}
