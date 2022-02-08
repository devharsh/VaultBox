//
//  test.cpp
//  VaultBox
//
//  Created by Devharsh Trivedi on 2/6/22.
//

#include "test.hpp"

int main() {
    try{
        std::vector<std::string>  vaultBox;
        std::vector<std::string>  symStore;
        std::vector<unsigned long> indexes;
        std::vector<unsigned long> indices;
        
        // SENDER
        
        std::vector<CryptoPP::byte> byteBox;
        std::string prevAlert;
        
        unsigned long totalAlertCount = 0;
        unsigned long indexCount = 0;
        unsigned long prevSeq = 0;
        
        for(unsigned long i=0; i<maxAlerts; i++) {
            indexes.push_back(i);
            indices.push_back(i);
            vaultBox.push_back("it is the default string.. for now");
        }
        
        unsigned int num_ranDev = shuffleIndexes(indexes);
        
        std::string password = "Super secret password";
        
        CryptoPP::SecByteBlock ekey(16), iv(16), akey(16);
        CryptoPP::SecByteBlock ekey2(16),iv2(16),akey2(16);
        
        DeriveKeyAndIV(password, "authenticated encryption example", 100,
                       ekey, ekey.size(), iv, iv.size(), akey, akey.size());
        
        ekey2 = ekey;
        iv2 = iv;
        akey2 = akey;
        
        for(int i=0; i<bufferSize; i++) {
            totalAlertCount++;
            std::string alert = std::to_string(totalAlertCount) + delimiter + "It is a string!";
            for (unsigned long j=0; j<redundancyFactor; j++) {
                indexCount = indexCount % maxAlerts;
                vaultBox[indexes[indexCount]] = encryptAlert(ekey, iv, akey, alert);
                
                std::string msg = vaultBox[indexes[indexCount]];
                forwardKeygen(msg, ekey, akey);
                
                CryptoPP::HexEncoder verify_encoder(new CryptoPP::FileSink(std::cout));
                std::string verify_digest;
                CryptoPP::SHA256 verify_hash;
                
                for(auto verify_str: vaultBox) {
                    verify_hash.Update((const CryptoPP::byte*)verify_str.data(), verify_str.size());
                }
                
                verify_digest.resize(verify_hash.DigestSize());
                verify_hash.Final((CryptoPP::byte*)&verify_digest[0]);
                
                if(logEnable) {
                    std::cout << "Digest: ";
                    CryptoPP::StringSource(verify_digest, true, new CryptoPP::Redirector(verify_encoder));
                    std::cout << std::endl;
                }
                
                indexCount++;
            }
        }
        
        std::string pass_c = "1234567812345678";
        CryptoPP::SecByteBlock key_c(reinterpret_cast<const CryptoPP::byte*>(pass_c.data()), pass_c.size());
        sendVaultBox(key_c, key_c, key_c, vaultBox, indices, symStore);
        
        // RECEIVER
        
        // randomly drop symbols to simulate noisy channel
        if(logEnable) { std::cout << "VaultBox size is " << vaultBox.size() << "\n"; }
        for(int f=0; f<(maxAlerts/12); f++) {
            vaultBox.erase(vaultBox.begin() + (std::rand()%vaultBox.size()));
        }
        if(logEnable) { std::cout << "VaultBox size is " << vaultBox.size() << "\n"; }
        
        iota(indices.begin(), indices.end(), 0);
        iota(indexes.begin(), indexes.end(), 0);
        readVaultBox(key_c, key_c, key_c, vaultBox, indices, symStore);
        std::mt19937 mtGen(num_ranDev);
        shuffle(indexes.begin(), indexes.end(), mtGen);
        //decryptAES_GCM_AEAD(ekey, iv, idxCnt);
        //decryptChaChaPoly(ekey, iv, idxCnt);
        decryptVaultBox(ekey2, iv2, akey2, indexCount, prevSeq, prevAlert, vaultBox, indexes);
        
        return 0;
    }
    
    catch(CryptoPP::BufferedTransformation::NoChannelSupport& e) {
        std::cerr << "Caught NoChannelSupport..." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    
    catch(CryptoPP::AuthenticatedSymmetricCipher::BadState& e) {
        std::cerr << "Caught BadState..." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    
    catch(CryptoPP::InvalidArgument& e) {
        std::cerr << "Caught InvalidArgument..." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    
    catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
    
    catch(std::bad_alloc& ba){
        std::cerr << "bad_alloc caught: " << ba.what() << std::endl;
        exit(1);
    }
    
    catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}
