//
//  main.cpp
//  VaultBox
//
//  Created by Devharsh Trivedi on 2/17/21.
//

#include <cryptopp/aes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
using namespace CryptoPP;

#include <iostream>
#include <string>
#include <vector>
#include <random>
using namespace std;

#define redundancyFactor 4
#define bufferSize 6
#define maxAlerts (redundancyFactor * bufferSize)
#define delimiter '?'

void shuffleIndexes();
void writeVaultBox(string alert, SecByteBlock& ekey, SecByteBlock& iv, SecByteBlock& akey);
void readVaultBox();

void DeriveKeyAndIV(const string& master, const string& salt,
                    unsigned int iterations,
                    SecByteBlock& ekey, unsigned int eksize,
                    SecByteBlock& iv, unsigned int vsize,
                    SecByteBlock& akey, unsigned int aksize);

void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey);

vector<string> vaultBox;
vector<unsigned long> indexes;

unsigned long totalAlertCount = 0;
unsigned long indexCount = 0;

int main(int argc, const char * argv[]) {
    /* Design:
     
     Two Apps:
     1. SAS
     2. SIEM
     
     and a configuration file?
     
     SAS
     - send buffer every 10 minutes to SIEM
     - buffer has 256 x 4 = 1024 encrypted alerts
     - alert = Enc (counter + alert + salt || HMAC)
     
     SIEM
     - if buffer not received anomaly is detected
     - decrypt alerts, verify HMAC, discard salt
     - identify missing counter
     - compare alerts with same counter */
    
    try {
        for(unsigned long i=0; i<maxAlerts; i++) {
            indexes.push_back(i);
            vaultBox.push_back("it is the default string.. for now");
        }
        
        shuffleIndexes();
        
        string password = "Super secret password";
        
        // For derived parameters
        SecByteBlock ekey(16), iv(16), akey(16);
        
        DeriveKeyAndIV(password, "authenticated encryption example", 100,
                       ekey, ekey.size(), iv, iv.size(), akey, akey.size());
        
        for(int i=0; i<4; i++)
        writeVaultBox("This is a string", ekey, iv, akey);
        
        //readVaultBox();
        
        return 0;
    }
    
    catch(const CryptoPP::Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }
    
    catch(std::exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }
}

// SAS performs this every heartbeat
void shuffleIndexes() {
    random_device ranDev;
    mt19937 mtGen(ranDev());
    shuffle(indexes.begin(), indexes.end(), mtGen);
}

// SAS calls this every alert
void writeVaultBox(string alert, SecByteBlock& ekey, SecByteBlock& iv, SecByteBlock& akey) {
    totalAlertCount++;
    indexCount = indexCount % maxAlerts;
    alert = to_string(totalAlertCount) + delimiter + alert;
    
    static const word32 flags = CryptoPP::HashVerificationFilter::HASH_AT_END |
    CryptoPP::HashVerificationFilter::PUT_MESSAGE |
    CryptoPP::HashVerificationFilter::THROW_EXCEPTION;
    
    for (int i=0; i<redundancyFactor; i++) {
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
        StringSource ss1(alert, true /*pumpAll*/,
                         new StreamTransformationFilter(encryptor,
                                                        new HashFilter(hmac1,
                                                                       new StringSink(cipher),
                                                                       true /*putMessage*/)));
        
        
        StringSource ss2(cipher, true /*pumpAll*/,
                         new HashVerificationFilter(hmac2,
                                                    new StreamTransformationFilter(decryptor,
                                                                                   new StringSink(recover)),
                                                    flags));
        
        PrintKeyAndIV(ekey, iv, akey);
        cout << "Message: " << alert << endl;
        
        cout << "Ciphertext+MAC: ";
        HexEncoder encoder(new FileSink(cout));
        
        encoder.Put((byte*)cipher.data(), cipher.size());
        encoder.MessageEnd(); cout << endl;
        
        cout << "Recovered: " << recover << endl;
        cout << endl;
        
        SecByteBlock new_key(reinterpret_cast<const byte*>(&cipher[0]), cipher.size());
        ekey = akey = SecByteBlock(new_key, 16);
        
        vaultBox[indexes[indexCount]] = alert;
        indexCount++;
    }
}

// SIEM
void readVaultBox() {
    for(unsigned long i=0; i<maxAlerts; i++) {
        cout << vaultBox[i] << endl;
    }
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
