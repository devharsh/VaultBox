//
//  main.cpp
//  VaultBox
//
//  Created by Devharsh Trivedi on 2/17/21.
//

#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

#include <iostream>
#include <string>
#include <vector>
#include <random>

using namespace std;

#define redundancyFactor 4
#define bufferSize 6 //256
#define maxAlerts (redundancyFactor * bufferSize)
#define delimiter '?'

void shuffleIndexes();
void writeVaultBox(string alert, SecByteBlock& key);
void readVaultBox();

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
        AutoSeededRandomPool prng;
        SecByteBlock key(50);
        prng.GenerateBlock(key, key.size());
        
        for(unsigned long i=0; i<maxAlerts; i++) {
            indexes.push_back(i);
            vaultBox.push_back("it is the default string.. for now");
        }
        
        shuffleIndexes();
        for(int i=0; i<4; i++)
        writeVaultBox("This is a string", key);
        readVaultBox();
        
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
void writeVaultBox(string alert, SecByteBlock& key) {
    totalAlertCount++;
    indexCount = indexCount % maxAlerts;
    alert = to_string(totalAlertCount) + delimiter + alert;
    
    HMAC< SHA256 > hmac(key, key.size());
    
    string alert_hmac;
    StringSource ss(alert, true,
                    new HashFilter(hmac, new StringSink(alert_hmac)));
    
    string alert_hmac_hex;
    StringSource ss2(alert_hmac, true,
                     new HexEncoder(new StringSink(alert_hmac_hex)));
    
    //NOTE: use "Encrypt then Authenticate (EtA)" and not "Encrypt and Authenticate (E&A)"
    //'AES-EAX' - Demonstrates encryption and decryption using AES in EAX mode (confidentiality and authentication)
    //'cryptopp-authenc' - Authenticated encryption and decryption using a block cipher in CBC mode and a HMAC
    //Encrypt then Authenticate (EtA) - IPSec
    //Encrypt and  Authenticate (E&A) - SSH
    
    alert = alert + delimiter + alert_hmac_hex;
    
    SecByteBlock newkey(reinterpret_cast<const byte*>(&alert_hmac[0]), alert_hmac.size());
    key = newkey;
    
    for (int i=0; i<redundancyFactor; i++) {
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
