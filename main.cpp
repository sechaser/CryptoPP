#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <sys/timeb.h>

#include "modes.h"
#include "aes.h"
#include "filters.h"

#include "AESencrypt.h"
#include "AESdecrypt.h"

int main(int argc, char* argv[]) {

    if(argc <  2)
    {
        std::cout<<"Please input a file"<<std::endl;
        exit(-1);
    }
    std::string img_name = argv[1];

    //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
    //bit). This key is secretly exchanged between two parties before communication
    //begins. DEFAULT_KEYLENGTH= 16 bytes
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );

    //CBC,CFB and OFB mode
    byte iv[CryptoPP::AES::BLOCKSIZE];
    memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

    struct timeb start, end;
    ftime(&start);

    std::string plaintext, ciphertext;
    std::ifstream in;
    in.open(img_name, std::ifstream::binary);

    char ch;
    while(in>>ch)
        plaintext += ch;

    AES_OFBencrypt(key, iv, plaintext, ciphertext);

    ftime(&end);
    std::cout<<(end.time - start.time) * 1000 + (end.millitm - start.millitm)<<std::endl;

    std::string dectext;
    AES_OFBdecrypt(key, iv, ciphertext, dectext);

    if(plaintext == dectext)
        std::cout<<"hello world"<<std::endl;

    system("pause");
    return 0;
}
