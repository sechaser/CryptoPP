#include "AESdecrypt.h"

#include "modes.h"
#include "filters.h"

void AES_ECBdecrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], std::string& ciphertext, std::string& dectext)
{
    CryptoPP::AES::Decryption AESdec(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::ECB_Mode_ExternalCipher::Decryption ECBdec(AESdec);
    CryptoPP::StreamTransformationFilter stfDecryptor(ECBdec, new CryptoPP::StringSink(dectext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
    stfDecryptor.MessageEnd();
}


void AES_CBCdecrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                          std::string& ciphertext, std::string& dectext)
{
    CryptoPP::AES::Decryption AESdec(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption CBCdec(AESdec, iv);
    CryptoPP::StreamTransformationFilter stfDecryptor(CBCdec, new CryptoPP::StringSink(dectext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
    stfDecryptor.MessageEnd();
}


void AES_CFBdecrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                          std::string& ciphertext, std::string& dectext)
{
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption CFBdec(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
    CryptoPP::StreamTransformationFilter stfDecryptor(CFBdec, new CryptoPP::StringSink(dectext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
    stfDecryptor.MessageEnd();
}


void AES_OFBdecrypt(byte (&key)[CryptoPP::AES::DEFAULT_KEYLENGTH], byte (&iv)[CryptoPP::AES::BLOCKSIZE],
                    std::string& ciphertext, std::string& dectext)
{
    CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption CFBdec(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
    CryptoPP::StreamTransformationFilter stfDecryptor(CFBdec, new CryptoPP::StringSink(dectext));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
    stfDecryptor.MessageEnd();
}
