//
//  lib.hpp
//  VaultBox
//
//  Created by Devharsh Trivedi on 2/6/22.
//

#ifndef lib_hpp
#define lib_hpp

#include <cryptopp/aes.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>

#include <stdio.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <cstdlib>
#include <vector>
#include <random>

#define redundancyFactor 3
#define bufferSize 100
#define maxAlerts (redundancyFactor * bufferSize)
#define delimiter '?'
#define TAG_SIZE 16
#define symSize (redundancyFactor * maxAlerts)
#define logEnable false

struct vbSymbol {
    std::vector<int> indices;
    std::string data;
};

unsigned int shuffleIndexes(std::vector<unsigned long>& indexes);

void sendVaultBox(CryptoPP::SecByteBlock ekey, CryptoPP::SecByteBlock iv, CryptoPP::SecByteBlock akey,
                  std::vector<std::string>& vaultBox, std::vector<unsigned long>& indices,
                  std::vector<vbSymbol>& symStore);

void DeriveKeyAndIV(const std::string& master, const std::string& salt, unsigned int iterations,
                    CryptoPP::SecByteBlock& ekey, unsigned long eksize,
                    CryptoPP::SecByteBlock& iv, unsigned long vsize,
                    CryptoPP::SecByteBlock& akey, unsigned long aksize);

std::string encryptAlert(CryptoPP::SecByteBlock ekey, CryptoPP::SecByteBlock iv,
                         CryptoPP::SecByteBlock akey, std::string pt_msg);

std::string encryptChaChaPoly(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, std::string pt_msg);

std::string encryptAES_GCM_AEAD(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, std::string pt_msg);

void readVaultBox(CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& iv, CryptoPP::SecByteBlock& akey,
                  std::vector<std::string>& vaultBox, std::vector<vbSymbol>& symStore);

std::string decryptAlert(CryptoPP::SecByteBlock ekey, CryptoPP::SecByteBlock iv,
                         CryptoPP::SecByteBlock akey, std::string pt_msg);

void decryptVaultBox(CryptoPP::SecByteBlock ekey, CryptoPP::SecByteBlock iv, CryptoPP::SecByteBlock akey,
                     unsigned long idxCnt, unsigned long& prevSeq, std::string& prevAlert,
                     std::vector<std::string>& vaultBox, std::vector<unsigned long>& indexes,
                     std::vector<CryptoPP::SecByteBlock>& ekeyMaster,
                     std::vector<CryptoPP::SecByteBlock>& akeyMaster);

void PrintKeyAndIV(CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& iv, CryptoPP::SecByteBlock& akey);

void sequenceChecker(std::string recover, std::string& prevAlert, unsigned long& prevSeq);

void identityChecker(std::string nextAlert, std::string prevAlert);

void decryptChaChaPoly(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, unsigned long idxCnt,
                       std::vector<std::string>& vaultBox, std::vector<unsigned long>& indexes);

void decryptAES_GCM_AEAD(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, unsigned long idxCnt,
                         std::vector<std::string>& vaultBox, std::vector<unsigned long>& indexes);

void forwardKeygen(CryptoPP::SecByteBlock genkey, CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& akey);

void fisherYatesShuffle(std::vector<unsigned long>& indices);

std::vector<double> ideal_distribution(int n);

std::vector<double> robust_distribution(int n);

#endif /* lib_hpp */
