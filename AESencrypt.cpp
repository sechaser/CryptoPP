#include "AESencrypt.h"

#include "modes.h"
#include "filters.h"

void AES_ECBencrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], std::string& plaintext, std::string& ciphertext)
{
    CryptoPP::AES::Encryption AESenc(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::ECB_Mode_ExternalCipher::Encryption ECBenc(AESenc);
    CryptoPP::StreamTransformationFilter stfEncryptor(ECBenc, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    stfEncryptor.MessageEnd();
}


void AES_CBCencrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext)
{
    CryptoPP::AES::Encryption AESenc(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption CBCenc(AESenc, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(CBCenc, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    stfEncryptor.MessageEnd();
}


void AES_CFBencrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext)
{
    CryptoPP::AES::Encryption AESenc(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CFB_Mode_ExternalCipher::Encryption CFBenc(AESenc, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(CFBenc, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    stfEncryptor.MessageEnd();
}

void AES_OFBencrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                    std::string& plaintext, std::string& ciphertext)
{
    CryptoPP::AES::Encryption AESenc(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::OFB_Mode_ExternalCipher::Encryption OFBenc(AESenc, iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(OFBenc, new CryptoPP::StringSink(ciphertext));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    stfEncryptor.MessageEnd();
}

