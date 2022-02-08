//
//  lib.cpp
//  VaultBox
//
//  Created by Devharsh Trivedi on 2/6/22.
//

#include "lib.hpp"

unsigned int shuffleIndexes(std::vector<unsigned long>& indexes) {
    std::random_device ranDev;
    unsigned int num_ranDev = ranDev();
    std::mt19937 mtGen(num_ranDev);
    shuffle(indexes.begin(), indexes.end(), mtGen);
    return num_ranDev;
}

void sendVaultBox(CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& iv, CryptoPP::SecByteBlock& akey,
                  std::vector<std::string>& vaultBox, std::vector<unsigned long>& indices,
                  std::vector<std::string>& symStore) {
    srand(seedVal);
    std::mt19937 mtGenS(seedVal);
    
    for(int i = 0; i < symSize; i++) {
        unsigned long degree = std::rand() % degreeVal;
        std::shuffle(indices.begin(), indices.end(), mtGenS);
        std::string cur_symbol = vaultBox[indices[0]];
        
        if(logEnable) {
            std::cout << degree << "\t";
            std::cout << indices[0] << ", ";
        }
        
        if(degree > 0) {
            for(unsigned long j = 1; j <= degree; j++) {
                long* newd1 = reinterpret_cast<long*>(&cur_symbol[0]);
                long* newd2 = reinterpret_cast<long*>(&vaultBox[indices[j]][0]);
                if(logEnable) { std::cout << indices[j] << ", "; }
                for(unsigned long q = 0; q < cur_symbol.length() / 8; q += 4)
                {
                    newd1[q] = newd1[q] ^ newd2[q];
                    newd1[q+1] = newd1[q+1] ^ newd2[q+1];
                    newd1[q+2] = newd1[q+2] ^ newd2[q+2];
                    newd1[q+3] = newd1[q+3] ^ newd2[q+3];
                }
            }
        }
        if(logEnable) { std::cout << "\n"; }
        cur_symbol = encryptAlert(ekey, iv, akey, cur_symbol);
        symStore.push_back(cur_symbol);
    }
}

void DeriveKeyAndIV(const std::string& master, const std::string& salt, unsigned int iterations,
                    CryptoPP::SecByteBlock& ekey, unsigned long eksize,
                    CryptoPP::SecByteBlock& iv, unsigned long vsize,
                    CryptoPP::SecByteBlock& akey, unsigned long aksize) {
    CryptoPP::SecByteBlock tb, ts(CryptoPP::SHA512::DIGESTSIZE), tm(CryptoPP::SHA512::DIGESTSIZE);
    CryptoPP::SHA512 hash;
    hash.CalculateDigest(ts, (const CryptoPP::byte*)salt.data(), salt.size());
    
    static const std::string s1 = "master key";
    tb = CryptoPP::SecByteBlock((const CryptoPP::byte*)master.data(), master.size()) +
    CryptoPP::SecByteBlock((const CryptoPP::byte*)s1.data(), s1.size());
    
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf;
    const CryptoPP::byte unused = 0;
    pbkdf.DeriveKey(tm, tm.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    iterations);
    
    static const std::string s2 = "encryption key";
    ekey.resize(eksize);
    tb = tm + CryptoPP::SecByteBlock((const CryptoPP::byte*)s2.data(), s2.size());
    pbkdf.DeriveKey(ekey, ekey.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    iterations);
    
    static const std::string s3 = "initialization vector";
    iv.resize(vsize);
    tb = tm + CryptoPP::SecByteBlock((const CryptoPP::byte*)s3.data(), s3.size());
    pbkdf.DeriveKey(iv, iv.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    iterations);
    
    static const std::string s4 = "authentication key";
    akey.resize(aksize);
    tb = tm + CryptoPP::SecByteBlock((const CryptoPP::byte*)s4.data(), s4.size());
    pbkdf.DeriveKey(akey, iv.size(),
                    unused,
                    tb, tb.size(),
                    ts, ts.size(),
                    iterations);
}

std::string encryptAlert(CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& iv,
                         CryptoPP::SecByteBlock& akey, std::string alert) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    
    encryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());
    hmac.SetKey(akey, akey.size());
    
    std::string cipher;
    CryptoPP::StringSource ss(alert, true /*pumpAll*/,
                              new CryptoPP::StreamTransformationFilter(encryptor,
                                                                       new CryptoPP::HashFilter(hmac,
                                                                                                new CryptoPP::StringSink(cipher),
                                                                                                true /*putMessage*/)));
    
    return cipher;
}

std::string encryptChaChaPoly(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, std::string alert) {
    CryptoPP::XChaCha20Poly1305::Encryption enc;
    CryptoPP::byte aad[] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    CryptoPP::byte ct[alert.size()], mac[16];
    
    std::string encode;
    CryptoPP::StringSource(alert, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encode)));
    
    enc.SetKeyWithIV(key, sizeof(key), iv, 24);
    enc.EncryptAndAuthenticate(ct, mac, sizeof(mac), iv, 24, aad, sizeof(aad), (const CryptoPP::byte*)alert.data(), alert.size());
    
    std::string cipher;
    CryptoPP::StringSource(ct, sizeof(ct), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(cipher)));
    
    std::string strMac;
    CryptoPP::StringSource(mac, sizeof(mac), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(strMac)));
    
    CryptoPP::byte rt[sizeof(ct)];
    CryptoPP::XChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(key, sizeof(key), iv, 24);
    
    const CryptoPP::byte* xmac = reinterpret_cast<const CryptoPP::byte*>(strMac.data());
    dec.DecryptAndVerify(rt, xmac, sizeof(xmac), iv, 24, aad, sizeof(aad), (const CryptoPP::byte*)cipher.data(), cipher.size());
    
    std::string decode;
    CryptoPP::StringSource(rt, sizeof(rt), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(decode)));
    
    std::string recover;
    CryptoPP::StringSource(decode, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(recover)));
    
    CryptoPP::SecByteBlock new_key(reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size());
    key = CryptoPP::SecByteBlock(new_key, 16);
    
    if(logEnable) {
        std::cout << "Plain: " << alert << std::endl;
        std::cout << "Encode: " << encode << std::endl;
        std::cout << "Cipher: " << cipher << std::endl;
        std::cout << "MAC: " << strMac << std::endl;
        std::cout << "Decode: " << decode << std::endl;
        std::cout << "Recover: " << recover << std::endl << std::endl;
    }
    
    return cipher + strMac;
}

std::string encryptAES_GCM_AEAD(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, std::string alert) {
    CryptoPP::GCM<CryptoPP::AES>::Encryption e;
    std::string cipher, encoded, recovered;
    e.SetKeyWithIV(key, key.size(), iv, iv.size());
    
    CryptoPP::AuthenticatedEncryptionFilter ef(e, new CryptoPP::StringSink(cipher), false, TAG_SIZE);
    
    ef.ChannelPut("AAD", (const CryptoPP::byte*)key.data(), key.size());
    ef.ChannelMessageEnd("AAD");
    ef.ChannelPut("", (const CryptoPP::byte*)alert.data(), alert.size());
    ef.ChannelMessageEnd("");
    
    CryptoPP::StringSource(cipher, true,
                           new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded), true, 16, ""));
    
    CryptoPP::SecByteBlock new_key(reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size());
    key = CryptoPP::SecByteBlock(new_key, 16);
    
    if(logEnable){
        std::cout << "plain text: " << alert << std::endl;
        std::cout << "cipher text: " << std::endl << " " << encoded << std::endl;
    }
    
    return cipher;
}

void readVaultBox(CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& iv, CryptoPP::SecByteBlock& akey,
                  std::vector<std::string>& vaultBox, std::vector<unsigned long>& indices,
                  std::vector<std::string>& symStore) {
    srand(seedVal);
    std::mt19937 mtGenR(seedVal);
    
    std::vector<std::string> bufferSymbols;
    std::vector<int> degreeSymbols;
    std::vector<std::vector<int>> indexSymbols;
    std::vector<int> doneSymbols;
    
    for(std::string stringRead : symStore) {
        bufferSymbols.push_back(decryptAlert(ekey, iv, akey, stringRead));
        int degree = std::rand() % degreeVal;
        degreeSymbols.push_back(degree);
        if(logEnable) { std::cout << degree << "\t"; }
        std::shuffle(indices.begin(), indices.end(), mtGenR);
        std::vector<int> degreeInsertion;
        for(int j=0; j<=degree; j++) {
            degreeInsertion.push_back(indices[j]);
            if(logEnable) { std::cout << indices[j] << ", "; }
        }
        sort(degreeInsertion.begin(), degreeInsertion.end());
        indexSymbols.push_back(degreeInsertion);
        if(logEnable) { std::cout << "\n"; }
    }
    
    unsigned long haltExit = 0;
    while(!degreeSymbols.empty()) {
        for(int k=0; k<degreeSymbols.size(); k++){
            if(degreeSymbols[k] == 0) {
                vaultBox[indexSymbols[k][0]] = bufferSymbols[k];
                doneSymbols.push_back(indexSymbols[k][0]);
                bufferSymbols.erase(bufferSymbols.begin() + k);
                degreeSymbols.erase(degreeSymbols.begin() + k);
                indexSymbols.erase(indexSymbols.begin() + k);
            } else if(degreeSymbols[k] > 0) {
                if(haltExit > (symSize * 10)) {
                    std::cerr << "Exiting..Not enough symbols to decode successfully!!" << "\n";
                    exit(1);
                }
                std::vector<int>::iterator it;
                for(int f: doneSymbols) {
                    it = std::find(indexSymbols[k].begin(), indexSymbols[k].end(), f);
                    if(it != indexSymbols[k].end()) {
                        for (int p = 0; p < bufferSymbols[k].length(); p++) {
                            bufferSymbols[k][p] = (bufferSymbols[k][p] ^ vaultBox[f][p]);
                        }
                        indexSymbols[k].erase(it);
                        degreeSymbols[k]--;
                    }
                }
                haltExit++;
            } else if(degreeSymbols[k] < 0) {
                bufferSymbols.erase(bufferSymbols.begin() + k);
                degreeSymbols.erase(degreeSymbols.begin() + k);
                indexSymbols.erase(indexSymbols.begin() + k);
            }
        }
    }
}

std::string decryptAlert(CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& iv,
                         CryptoPP::SecByteBlock& akey, std::string alert) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    
    CryptoPP::word32 flags = CryptoPP::HashVerificationFilter::HASH_AT_END |
    CryptoPP::HashVerificationFilter::PUT_MESSAGE |
    CryptoPP::HashVerificationFilter::THROW_EXCEPTION;
    
    decryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());
    hmac.SetKey(akey, akey.size());
    std::string recover;
    CryptoPP::StringSource ss(alert, true /*pumpAll*/,
                              new CryptoPP::HashVerificationFilter(hmac,
                                                                   new CryptoPP::StreamTransformationFilter(decryptor,
                                                                                                            new CryptoPP::StringSink(recover)),
                                                                   flags));
    return recover;
}

void decryptVaultBox(CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& iv, CryptoPP::SecByteBlock& akey,
                     unsigned long idxCnt, unsigned long& prevSeq, std::string &prevAlert,
                     std::vector<std::string>& vaultBox, std::vector<unsigned long>& indexes) {
    for (unsigned long i=0; i<idxCnt; i++) {
        std::string recover = decryptAlert(ekey, iv, akey, vaultBox[indexes[i]]);
        
        if(logEnable) {
            PrintKeyAndIV(ekey, iv, akey);
            
            std::cout << "Ciphertext+MAC: ";
            CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
            encoder.Put((CryptoPP::byte*)vaultBox[indexes[i]].data(), vaultBox[indexes[i]].size());
            encoder.MessageEnd();
            std::cout << std::endl;
            
            std::cout << "Recovered: " << recover << std::endl;
            std::cout << std::endl;
        }
        
        if(i == 0)
            prevAlert.assign(recover);
        
        std::string msg = vaultBox[indexes[i]];
        forwardKeygen(msg, ekey, akey);
        
        sequenceChecker(recover, prevAlert, prevSeq);
        vaultBox[indexes[i]] = recover;
    }
}

void PrintKeyAndIV(CryptoPP::SecByteBlock& ekey,
                   CryptoPP::SecByteBlock& iv,
                   CryptoPP::SecByteBlock& akey) {
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
    
    std::cout << "AES key: ";
    encoder.Put(ekey.data(), ekey.size());
    encoder.MessageEnd();
    std::cout << std::endl;
    
    std::cout << "AES IV: ";
    encoder.Put(iv.data(), iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;
    
    std::cout << "HMAC key: ";
    encoder.Put(akey.data(), akey.size());
    encoder.MessageEnd();
    std::cout << std::endl;
}

void sequenceChecker(std::string recover, std::string& prevAlert, unsigned long& prevSeq) {
    std::string::size_type pos = recover.find(delimiter);
    unsigned long nextSeq = std::stoul(recover.substr(0, pos), nullptr, 0);
    
    if(nextSeq - prevSeq == 1) {}
    else if(nextSeq - prevSeq == 0) { identityChecker(recover, prevAlert); }
    else { std::cout << "missing sequence" << std::endl; }
    
    prevSeq = nextSeq;
    prevAlert.assign(recover);
}

void identityChecker(std::string nextAlert, std::string prevAlert) {
    if(prevAlert.compare(nextAlert) != 0)
        std::cout << "Error: Alert mismatch!!" << std::endl;
}

void decryptChaChaPoly(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, unsigned long idxCnt,
                       std::vector<std::string>& vaultBox, std::vector<unsigned long>& indexes) {
    CryptoPP::XChaCha20Poly1305::Decryption dec;
    CryptoPP::byte aad[] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    
    for (unsigned long i=0; i<idxCnt; i++) {
        std::string plain = vaultBox[indexes[i]];
        std::string cipher = plain.substr(0, plain.length() - 32);
        std::string strMAC = plain.substr(plain.length() - 32, 32);
        
        CryptoPP::byte rt[sizeof(cipher)];
        dec.SetKeyWithIV(key, sizeof(key), iv, 24);
        dec.DecryptAndVerify(rt, reinterpret_cast<const CryptoPP::byte*>(strMAC.data()), strMAC.size(), iv, 24, aad, sizeof(aad), reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size());
        
        std::string recover;
        CryptoPP::StringSource(rt, sizeof(rt), true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(recover)));
        CryptoPP::SecByteBlock new_key(reinterpret_cast<const CryptoPP::byte*>(plain.data()), plain.size());
        key = CryptoPP::SecByteBlock(new_key, 16);
        
        if(logEnable) {
            std::cout << cipher << std::endl;
            std::cout << strMAC << std::endl;
            std::cout << recover << std::endl;
        }
    }
}

void decryptAES_GCM_AEAD(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, unsigned long idxCnt,
                         std::vector<std::string>& vaultBox, std::vector<unsigned long>& indexes) {
    CryptoPP::GCM<CryptoPP::AES>::Decryption d;
    
    for (unsigned long i=0; i<idxCnt; i++) {
        std::string cipher = vaultBox[indexes[i]];
        
        d.SetKeyWithIV(key, key.size(), iv, iv.size());
        
        std::string enc = cipher.substr(0, cipher.length() - TAG_SIZE);
        std::string mac = cipher.substr(cipher.length() - TAG_SIZE);
        
        CryptoPP::AuthenticatedDecryptionFilter df(d, NULL,
                                                   CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                                   CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE);
        
        df.ChannelPut("", (const CryptoPP::byte*)mac.data(), mac.size());
        df.ChannelPut("AAD", (const CryptoPP::byte*)key.data(), key.size());
        df.ChannelPut("", (const CryptoPP::byte*)enc.data(), enc.size());
        df.ChannelMessageEnd("AAD");
        df.ChannelMessageEnd("");
        
        std::string retrieved;
        size_t n = (size_t) - 1;
        
        df.SetRetrievalChannel("");
        n = (size_t) df.MaxRetrievable();
        retrieved.resize(n);
        
        if(n > 0) { df.Get((CryptoPP::byte*)retrieved.data(), n); }
        if(logEnable) { std::cout << "recovered text: " << std::endl << " " << retrieved << std::endl; }
        vaultBox[indexes[i]] = retrieved;
        
        CryptoPP::SecByteBlock new_key(reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size());
        key = CryptoPP::SecByteBlock(new_key, 16);
    }
}

void forwardKeygen(std::string msg, CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& akey) {
    std::string digest;
    CryptoPP::SHA256 hash;
    hash.Update((const CryptoPP::byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);
    
    std::string half = digest.substr(0, digest.length()/2);
    std::string otherHalf = digest.substr(digest.length()/2);
    CryptoPP::SecByteBlock new_key(reinterpret_cast<const CryptoPP::byte*>(&half[0]), half.size());
    CryptoPP::SecByteBlock new_key2(reinterpret_cast<const CryptoPP::byte*>(&otherHalf[0]), otherHalf.size());
    ekey = CryptoPP::SecByteBlock(new_key, 16);
    akey = CryptoPP::SecByteBlock(new_key2,16);
}
