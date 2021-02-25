/*
 1. add line "using CryptoPP::byte;"
 
 2. compile using "% g++ -DDEBUG=1 -g3 -Og -Wall -Wextra -Wno-unused-parameter -I/usr/local/include/cryptopp cryptopp-authenc.cpp -lcryptopp"
 
 3. run program
 % ./a.out
 Password: Super secret password
 AES key: C08126FBECA7E2BE71B69FE92570A991
 AES IV: BCEB5407D68912C266B9045A5DD007CB
 HMAC key: EBBECB1D0A5B52F306B0F328877E057A
 Message: Now is the time for all good men to come to the aide of their country
 Ciphertext+MAC: 880EBA2190A039E94DA2CBBB0F46AA238879D9AE6BD8AFF5E141FF55B4B7D48A3A58B0910DADB9CEF2A7CC7C2954538ABFBF761F9602ED3C1BA8C6C645F96EF48FF9D3ACFA9ABB0C5A4906C00D2C17E93CBA8B64D4493B45F7F95C64EB7F947B5C9516AA100E6C02427CF254556DE94C
 Recovered: Now is the time for all good men to come to the aide of their country
 */

// g++ -DDEBUG=1 -g3 -Og -Wall -Wextra -Wno-unused-parameter -I/usr/local/include/cryptopp cryptopp-authenc.cpp -o cryptopp-authenc.exe /usr/local/lib/libcryptopp.a
// g++ -DNDEBUG=1 -g3 -O2 -Wall -Wextra -Wno-unused-parameter -I/usr/local/include/cryptopp cryptopp-authenc.cpp -o cryptopp-authenc.exe /usr/local/lib/libcryptopp.a

#include <iostream>
using std::ostream;
using std::cout;
using std::cerr;
using std::endl;
using std::ios;

#include <string>
using std::string;

#include <cryptopp/cryptlib.h>
using CryptoPP::lword;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::Exception;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;
using CryptoPP::SecBlock;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::HashFilter;

#include <cryptopp/files.h>
using CryptoPP::FileSink;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;
using CryptoPP::SHA512;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/modes.h>
using CryptoPP::CBC_Mode;

#include <cryptopp/pwdbased.h>
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include <cryptopp/hmac.h>
using CryptoPP::HMAC;

using CryptoPP::byte;

void DeriveKeyAndIV(const string& master, const string& salt,
                    unsigned int iterations,
                    SecByteBlock& ekey, unsigned int eksize,
                    SecByteBlock& iv, unsigned int vsize,
                    SecByteBlock& akey, unsigned int aksize);

void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey);

// g++ -DDEBUG=1 -g3 -O1 -Wall -Wextra -Wno-unused-parameter -I/usr/local/include/cryptopp cryptopp-authenc.cpp /usr/local/lib/libcryptopp.a -o cryptopp-authenc.exe

int main(int argc, char* argv[])
{
    (void)argc; (void)argv;
    
    string password = "Super secret password";
    if(argc >= 2 && argv[1] != NULL)
        password = string(argv[1]);
    
    string message = "Now is the time for all good men to come to the aide of their country";
    if(argc >= 3 && argv[2] != NULL)
        message = string(argv[2]);
    
    try {
        
        // For derived parameters
        SecByteBlock ekey(16), iv(16), akey(16);
        
        DeriveKeyAndIV(password, "authenticated encryption example", 100,
                       ekey, ekey.size(), iv, iv.size(), akey, akey.size());
        
        // Authenticate and decrypt data
        static const word32 flags = CryptoPP::HashVerificationFilter::HASH_AT_END |
        CryptoPP::HashVerificationFilter::PUT_MESSAGE |
        CryptoPP::HashVerificationFilter::THROW_EXCEPTION;
        
        for(int i=0; i<4; i++) {
            // Create and key objects
            CBC_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());
            CBC_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());
            HMAC< SHA256> hmac1;
            hmac1.SetKey(akey, akey.size());
            HMAC< SHA256> hmac2;
            hmac2.SetKey(akey, akey.size());
            
            // Encrypt and authenticate data
            string cipher, recover;
            StringSource ss1(message, true /*pumpAll*/,
                             new StreamTransformationFilter(encryptor,
                                                            new HashFilter(hmac1,
                                                                           new StringSink(cipher),
                                                                           true /*putMessage*/)));
            
            
            StringSource ss2(cipher, true /*pumpAll*/,
                             new HashVerificationFilter(hmac2,
                                                        new StreamTransformationFilter(decryptor,
                                                                                       new StringSink(recover)),
                                                        flags));
            
            // Print stuff
            cout << "Password: " << password << endl;
            
            PrintKeyAndIV(ekey, iv, akey);
            cout << "Message: " << message << endl;
            
            cout << "Ciphertext+MAC: ";
            HexEncoder encoder(new FileSink(cout));
            
            encoder.Put((byte*)cipher.data(), cipher.size());
            encoder.MessageEnd(); cout << endl;
            
            cout << "Recovered: " << recover << endl;
            cout << endl;
            
            SecByteBlock new_key(reinterpret_cast<const byte*>(&cipher[0]), cipher.size());
            ekey = akey = SecByteBlock(new_key, 16);
            //hmac1.SetKey(akey, akey.size());
            //hmac2.SetKey(akey, akey.size());
        }
    }
    catch(CryptoPP::Exception& ex)
    {
        cerr << ex.what() << endl;
    }
    
    return 0;
}

void DeriveKeyAndIV(const string& master, const string& salt,
                    unsigned int iterations,
                    SecByteBlock& ekey, unsigned int eksize,
                    SecByteBlock& iv, unsigned int vsize,
                    SecByteBlock& akey, unsigned int aksize)
{
    
    SecByteBlock tb, ts(SHA512::DIGESTSIZE), tm(SHA512::DIGESTSIZE);
    
    // Temporary salt, stretch size.
    SHA512 hash;
    hash.CalculateDigest(ts, (const byte*)salt.data(), salt.size());
    
    static const string s1 = "master key";
    tb = SecByteBlock((const byte*)master.data(), master.size()) + SecByteBlock((const byte*)s1.data(), s1.size());
    
    PKCS5_PBKDF2_HMAC<SHA512> pbkdf;
    const byte unused = 0;
    pbkdf.DeriveKey(tm, tm.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);
    
    static const string s2 = "encryption key";
    ekey.resize(eksize);
    tb = tm + SecByteBlock((const byte*)s2.data(), s2.size());
    pbkdf.DeriveKey(ekey, ekey.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);
    
    static const string s3 = "initialization vector";
    iv.resize(vsize);
    tb = tm + SecByteBlock((const byte*)s3.data(), s3.size());
    pbkdf.DeriveKey(iv, iv.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);
    
    static const string s4 = "authentication key";
    akey.resize(aksize);
    tb = tm + SecByteBlock((const byte*)s4.data(), s4.size());
    pbkdf.DeriveKey(akey, iv.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    100);
}

void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey)
{
    // Print them
    HexEncoder encoder(new FileSink(cout));
    
    cout << "AES key: ";
    encoder.Put(ekey.data(), ekey.size());
    encoder.MessageEnd(); cout << endl;
    
    cout << "AES IV: ";
    encoder.Put(iv.data(), iv.size());
    encoder.MessageEnd(); cout << endl;
    
    cout << "HMAC key: ";
    encoder.Put(akey.data(), akey.size());
    encoder.MessageEnd(); cout << endl;
}
