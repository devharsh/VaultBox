//
//  main.cpp
//  PillarBox
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
        // iota(indexes.begin(), indexes.end(), 0);
        
        for(unsigned long i=0; i<maxAlerts; i++) {
            indexes.push_back(i);
            vaultBox.push_back("it is the default string.. for now");
        }
        
        shuffleIndexes();
        for(int i=0; i<4; i++)
        writeVaultBox("This is a string", key);
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
void writeVaultBox(string alert, SecByteBlock& key) {
    totalAlertCount++;
    indexCount = indexCount % maxAlerts;
    alert = to_string(totalAlertCount) + delimiter + alert;
    
    string encoded;
    encoded.clear();
    StringSource ss1(key, key.size(), true,
                     new HexEncoder(new StringSink(encoded)));
    
    //cout << "key: " << encoded << endl;
    cout << "plain text: " << alert << endl;
    
    HMAC< SHA256 > hmac(key, key.size());
    StringSource ss(alert, true,
                    new HashFilter(hmac, new StringSink(alert)));
    
    SecByteBlock newkey(reinterpret_cast<const byte*>(&alert[0]), alert.size());
    key = newkey;
    
    encoded.clear();
    StringSource ss2(alert, true,
                     new HexEncoder(new StringSink(encoded)));
    cout << "hmac: " << encoded << endl;
    
    for (int i=0; i<redundancyFactor; i++) {
        vaultBox[indexes[indexCount]] = encoded;
        indexCount++;
    }
}

// SIEM
void readVaultBox() {
    for(unsigned long i=0; i<maxAlerts; i++) {
        cout << vaultBox[i] << endl;
    }
}
