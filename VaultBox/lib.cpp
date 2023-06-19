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

void sendVaultBox(CryptoPP::SecByteBlock ekey, CryptoPP::SecByteBlock iv, CryptoPP::SecByteBlock akey,
                  std::vector<std::string>& vaultBox, std::vector<unsigned long>& indices,
                  std::vector<vbSymbol>& symStore) {
    // std::mt19937 mtGenS;

    // Option 1 - True RNG
    // std::random_device rd;

    // Option 2 - Robust soliton distribution for degree
    std::vector<double> probabilities = robust_distribution(maxAlerts);
    std::vector<long>   discreteD(probabilities.size(), 0);

    for(int p_this = 0; p_this < probabilities.size(); p_this++) {
        discreteD[p_this] = lround(1e6 * probabilities[p_this]);
    }

    std::discrete_distribution<long> ranD(discreteD.begin(), discreteD.end());
    std::default_random_engine e;


    for(int i = 0; i < symSize; i++) {
        unsigned long degree;
        if(i == 0) { degree = 0; }
        //else if(i > 0) {
        else {
            // Option 1 - Uniform random distribution
            // degree = rd() % (maxAlerts / 2);

            // Option 2 - Robust soliton distribution
            degree = ranD(e) - 1;
        }
        //else { exit(1); }

        // Option 1 for shuffle - deprecared in C++14
        // std::random_shuffle(indices.begin(), indices.end());
        // Option 2 for shuffle
        // std::shuffle(indices.begin(), indices.end(), mtGenS);
        // Option 3 for shuffle
        fisherYatesShuffle(indices);

        vbSymbol cur_symbol;
        cur_symbol.data= vaultBox[indices[0]];
        cur_symbol.indices.push_back(indices[0]);

        if(logEnable) {
            std::cout << degree << "\t";
            std::cout << indices[0] << ", ";
        }

        if(degree > 0) {
            for(unsigned long j = 1; j <= degree; j++) {
                cur_symbol.indices.push_back(indices[j]);
                long* newd1 = reinterpret_cast<long*>(&cur_symbol.data[0]);
                long* newd2 = reinterpret_cast<long*>(&vaultBox[indices[j]][0]);
                if(logEnable) { std::cout << indices[j] << ", "; }
                for(unsigned long q = 0; q < cur_symbol.data.length() / 8; q += 4)
                {
                    newd1[q] = newd1[q] ^ newd2[q];
                    newd1[q+1] = newd1[q+1] ^ newd2[q+1];
                    newd1[q+2] = newd1[q+2] ^ newd2[q+2];
                    newd1[q+3] = newd1[q+3] ^ newd2[q+3];
                }
            }
        }

        if(logEnable) { std::cout << "\n"; }
        cur_symbol.data = encryptAlert(ekey, iv, akey, cur_symbol.data);
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

std::string encryptAlert(CryptoPP::SecByteBlock ekey, CryptoPP::SecByteBlock iv,
                         CryptoPP::SecByteBlock akey, std::string pt_msg) {
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());

    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    hmac.SetKey(akey, akey.size());

    std::string cipher;
    CryptoPP::StringSource ss(pt_msg, true /*pumpAll*/,
                              new CryptoPP::StreamTransformationFilter(encryptor,
                                                                       new CryptoPP::HashFilter(hmac,
                                                                                                new CryptoPP::StringSink(cipher),
                                                                                                true /*putMessage*/)));

    return cipher;
}

std::string encryptChaChaPoly(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, std::string pt_msg) {
    CryptoPP::XChaCha20Poly1305::Encryption enc;
    CryptoPP::byte aad[] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    CryptoPP::byte ct[pt_msg.size()], mac[16];

    std::string encode;
    CryptoPP::StringSource(pt_msg, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encode)));

    enc.SetKeyWithIV(key, sizeof(key), iv, 24);
    enc.EncryptAndAuthenticate(ct, mac, sizeof(mac), iv, 24, aad, sizeof(aad), (const CryptoPP::byte*)pt_msg.data(), pt_msg.size());

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
        std::cout << "Plain: " << pt_msg << "\n";
        std::cout << "Encode: " << encode << "\n";
        std::cout << "Cipher: " << cipher << "\n";
        std::cout << "MAC: " << strMac << "\n";
        std::cout << "Decode: " << decode << "\n";
        std::cout << "Recover: " << recover << "\n" << "\n";
    }

    return cipher + strMac;
}

std::string encryptAES_GCM_AEAD(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, std::string const& pt_msg) {
    CryptoPP::GCM<CryptoPP::AES>::Encryption e;
    std::string cipher, encoded, recovered;
    e.SetKeyWithIV(key, key.size(), iv, iv.size());

    CryptoPP::AuthenticatedEncryptionFilter ef(e, new CryptoPP::StringSink(cipher), false, TAG_SIZE);

    ef.ChannelPut("AAD", (const CryptoPP::byte*)key.data(), key.size());
    ef.ChannelMessageEnd("AAD");
    ef.ChannelPut("", (const CryptoPP::byte*)pt_msg.data(), pt_msg.size());
    ef.ChannelMessageEnd("");

    CryptoPP::StringSource(cipher, true,
                           new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded), true, 16, ""));

    CryptoPP::SecByteBlock new_key(reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size());
    key = CryptoPP::SecByteBlock(new_key, 16);

    if(logEnable) {
        std::cout << "plain text: " << pt_msg << "\n";
        std::cout << "cipher text: " << "\n" << " " << encoded << "\n";
    }

    return cipher;
}

void readVaultBox(CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& iv, CryptoPP::SecByteBlock& akey,
                  std::vector<std::string>& vaultBox, std::vector<vbSymbol>& symStore) {
    std::vector<std::string> bufferSymbols;
    std::vector<int> degreeSymbols;
    std::vector< std::vector<int> > indexSymbols;
    std::vector<int> doneSymbols;

    for(unsigned long numSym = 0; numSym < symStore.size(); numSym++) {
        vbSymbol cur_sym = symStore[numSym];

        bufferSymbols.push_back(decryptAlert(ekey, iv, akey, cur_sym.data));
        int degree = cur_sym.indices.size() - 1;
        degreeSymbols.push_back(degree);
        if(logEnable) { std::cout << degree << "\t"; }

        std::vector<int> degreeInsertion;
        for(int j=0; j<=degree; j++) {
            degreeInsertion.push_back(cur_sym.indices[j]);
            if(logEnable) { std::cout << cur_sym.indices[j] << ", "; }
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
                if(haltExit > (symSize * 100)) {
                    std::cout << "\nExiting..Not enough symbols to decode successfully!!\n";
                    exit(0);
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

std::string decryptAlert(CryptoPP::SecByteBlock ekey, CryptoPP::SecByteBlock iv,
                         CryptoPP::SecByteBlock akey, std::string pt_msg) {
    if(pt_msg.empty()) { std::cout << "skipping decryption.. empty message" << "\n"; }

    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(ekey, ekey.size(), iv, iv.size());

    CryptoPP::HMAC<CryptoPP::SHA256> hmac;
    hmac.SetKey(akey, akey.size());

    CryptoPP::word32 flags = CryptoPP::HashVerificationFilter::HASH_AT_END |
    CryptoPP::HashVerificationFilter::PUT_MESSAGE |
    CryptoPP::HashVerificationFilter::THROW_EXCEPTION;

    std::string recover;
    CryptoPP::StringSource ss(pt_msg, true /*pumpAll*/,
                              new CryptoPP::HashVerificationFilter(hmac,
                                                                   new CryptoPP::StreamTransformationFilter(decryptor,
                                                                                                            new CryptoPP::StringSink(recover)),
                                                                   flags));
    return recover;
}

void decryptVaultBox(CryptoPP::SecByteBlock ekey, CryptoPP::SecByteBlock iv, CryptoPP::SecByteBlock akey,
                     unsigned long idxCnt, unsigned long& prevSeq, std::string &prevAlert,
                     std::vector<std::string>& vaultBox, std::vector<unsigned long>& indexes,
                     std::vector<CryptoPP::SecByteBlock>& ekeyMaster,
                     std::vector<CryptoPP::SecByteBlock>& akeyMaster) {
    for (unsigned long i=0; i<maxAlerts; i++) {
        if(i < idxCnt) {
            forwardKeygen(ekey, ekeyMaster[indexes[i]], akeyMaster[indexes[i]]);
            ekey = ekeyMaster[indexes[i]];
        }

        std::string recover = decryptAlert(ekeyMaster[indexes[i]], iv, akeyMaster[indexes[i]], vaultBox[indexes[i]]);

        if(logEnable) {
            PrintKeyAndIV(ekey, iv, akey);

            std::cout << "Ciphertext+MAC: ";
            CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
            encoder.Put((CryptoPP::byte*)vaultBox[indexes[i]].data(), vaultBox[indexes[i]].size());
            encoder.MessageEnd();
            std::cout << "\n";

            std::cout << "Recovered: " << recover << "\n";
            std::cout << "\n";
        }

        if(i < idxCnt) {
            if(i == 0) { prevAlert.assign(recover); }
            sequenceChecker(recover, prevAlert, prevSeq);
            vaultBox[indexes[i]] = recover;
        }
    }
}

void PrintKeyAndIV(CryptoPP::SecByteBlock& ekey,
                   CryptoPP::SecByteBlock& iv,
                   CryptoPP::SecByteBlock& akey) {
    CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));

    std::cout << "ekey: ";
    encoder.Put(ekey.data(), ekey.size());
    encoder.MessageEnd();
    std::cout << "\n";

    std::cout << "iv: ";
    encoder.Put(iv.data(), iv.size());
    encoder.MessageEnd();
    std::cout << "\n";

    std::cout << "akey: ";
    encoder.Put(akey.data(), akey.size());
    encoder.MessageEnd();
    std::cout << "\n";

    std::cout << "\n";
}

void sequenceChecker(std::string recover, std::string& prevAlert, unsigned long& prevSeq) {
    std::string::size_type pos = recover.find(delimiter);
    unsigned long nextSeq = std::stoul(recover.substr(0, pos), nullptr, 0);

    if(nextSeq - prevSeq == 1) {}
    else if(nextSeq - prevSeq == 0) { identityChecker(recover, prevAlert); }
    else { std::cout << prevSeq << "\t" << nextSeq << "\t" << "missing sequence" << "\n"; }

    prevSeq = nextSeq;
    prevAlert.assign(recover);
}

void identityChecker(std::string const& nextAlert, std::string const& prevAlert) {
    if(prevAlert.compare(nextAlert) != 0) { std::cout << "Error: Alert mismatch!!" << "\n"; }
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
            std::cout << cipher << "\n";
            std::cout << strMAC << "\n";
            std::cout << recover << "\n";
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
        if(logEnable) { std::cout << "recovered text: " << "\n" << " " << retrieved << "\n"; }
        vaultBox[indexes[i]] = retrieved;

        CryptoPP::SecByteBlock new_key(reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size());
        key = CryptoPP::SecByteBlock(new_key, 16);
    }
}

void forwardKeygen(CryptoPP::SecByteBlock genkey, CryptoPP::SecByteBlock& ekey, CryptoPP::SecByteBlock& akey) {
    std::string digest;
    CryptoPP::SHA256 hash;

    hash.Update(genkey.data(), genkey.size());
    digest.resize(hash.DigestSize());
    hash.Final((CryptoPP::byte*)&digest[0]);

    std::string half = digest.substr(0, digest.length()/2);
    std::string otherHalf = digest.substr(digest.length()/2);

    CryptoPP::SecByteBlock new_key(reinterpret_cast<const CryptoPP::byte*>(&half[0]), half.size());
    CryptoPP::SecByteBlock new_key2(reinterpret_cast<const CryptoPP::byte*>(&otherHalf[0]), otherHalf.size());

    ekey = CryptoPP::SecByteBlock(new_key, 16);
    akey = CryptoPP::SecByteBlock(new_key2,16);
}

void fisherYatesShuffle(std::vector<unsigned long>& indices) {
    for (int i = 0; i < indices.size() - 1; i++) {
        int j = i + std::rand() % (indices.size() - i);
        std::swap(indices[i], indices[j]);
    }
}

std::vector<double> ideal_distribution(int n) {
    if(n < 1) { throw std::logic_error("n should be at least 1!"); }

    double sum = 0.0;
    std::vector<double> probabilities(n + 1);

    // calculate probabilities of ideal_distribution
    probabilities[0] = 0;
    probabilities[1] = 1 / (double)n;
    for(int i = 2; i <= n; ++i) { probabilities[i] = 1 / (double)(i * (i - 1)); }

    // test : sum of probabilities must equal to 1
    for(double number : probabilities) { sum += number; }
    if(abs(1 - sum) > 0.000001) {
        std::cerr << "sum : " << sum << std::endl;
        throw std::runtime_error("sum of probabilities not equal to 1!");
    }

    return probabilities;
}

std::vector<double> robust_distribution(int n) {
    double RFP = 0.01;
    int m = n / 2 + 1;
    double sum = 0.0;

    std::vector<double> probabilities(n + 1, 0);
    std::vector<double> ideal_pros = ideal_distribution(n);

    // calculate probabilities of robust_distribution
    for(int i = 1; i < m; ++i) { probabilities[i] = 1 / (double)(i * m); }
    probabilities[m] = log(n / ((double)m * RFP)) / (double)m;

    for(int i = 0; i <= n; ++i) { probabilities[i] += ideal_pros[i]; }
    for(double number : probabilities) { sum += number; }
    for(double& num : probabilities) { num /= sum; }

    // test : sum of probabilities must equal to 1
    sum = 0;
    for(double number : probabilities) { sum += number; }
    if(abs(1 - sum) > 0.000001) {
        std::cerr << "sum : " << sum << std::endl;
        throw std::runtime_error("sum of probabilities not equal to 1!");
    }

    return probabilities;
}
