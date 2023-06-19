//
//  test.cpp
//  VaultBox
//
//  Created by Devharsh Trivedi on 2/6/22.
//

#include "test.hpp"

int main() {
    try{
        
        // SENDER global variables
        unsigned long totalAlertCount = 0;
        std::vector<std::string> vaultBox;
        for(unsigned long i=0; i<maxAlerts; i++) { vaultBox.push_back("it is the default string.. for now"); }
        
        // RECEIVER global variables
        std::vector<CryptoPP::SecByteBlock> ekeyMaster(maxAlerts);
        std::vector<CryptoPP::SecByteBlock> akeyMaster(maxAlerts);
        std::string prevAlert;
        unsigned long prevSeq = 0;
        
        // COMMON global variables
        std::string password = "Super secret password";
        std::string pass_c = "FEDCBA9876543210";
        
        
        // simulate sessions
        for(int isession = 0; isession < 4; isession++) {
            
            // SENDER session variables
            std::vector<vbSymbol>     symStore;
            std::vector<unsigned long> indexes;
            std::vector<unsigned long> indices;
            
            unsigned long indexCount = 0;
            
            for(unsigned long i=0; i<maxAlerts; i++) {
                indexes.push_back(i);
                indices.push_back(i);
            }
            
            unsigned int num_ranDev = shuffleIndexes(indexes);
            CryptoPP::SecByteBlock ekey(16), iv(16), akey(16);
            DeriveKeyAndIV(password, "authenticated encryption example", 100,
                           ekey, ekey.size(), iv, iv.size(), akey, akey.size());
            
            
            // RECEIVER session variables
            unsigned int num_ranDev2 = num_ranDev;
            CryptoPP::SecByteBlock ekey2(16),iv2(16),akey2(16);
            ekey2 = ekey;
            iv2 = iv;
            akey2 = akey;
            
            
            if(logEnable) { PrintKeyAndIV(ekey, iv, akey); }
            
            // to simulate different message size for each session
            for(int i = 0; i < bufferSize /*- isession*/; i++) {
                totalAlertCount++;
                std::string alert = std::to_string(totalAlertCount) + delimiter + "It is a string!";
                
                for (unsigned long j=0; j<redundancyFactor; j++) {
                    indexCount = indexCount % maxAlerts;
                    
                    forwardKeygen(ekey, ekey, akey);
                    vaultBox[indexes[indexCount]] = encryptAlert(ekey, iv, akey, alert);
                    
                    // subroutine to check vaultBox[] hash periodically
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
                        std::cout << "\n";
                    }
                    
                    indexCount++;
                }
            }
            
            // randomly change messages to simulate malicious modifications
            for(int c = 0; c < 0/*maxAlerts/8*/; c++) {
                int modId = std::rand()%maxAlerts;
                vaultBox[modId] = "it is the default string.. for now";
                if(logEnable) { std::cout << modId << "\n"; }
            }
            
            if(logEnable) {
                std::cout << "\n";
                for(std::string p_this: vaultBox) { std::cout << p_this << "\n"; }
                std::cout << "\n";
            }
            
            CryptoPP::SecByteBlock key_c(reinterpret_cast<const CryptoPP::byte*>(pass_c.data()), pass_c.size());
            sendVaultBox(key_c, key_c, key_c, vaultBox, indices, symStore);
            
            
            // RECEIVER session variables
            std::vector<std::string>   r_vaultBox(maxAlerts);
            std::vector<unsigned long> r_indexes (maxAlerts);
            
            if(logEnable) { std::cout << "\nTotal symbols are " << symStore.size() << "\n\n"; }
            
            // randomly drop symbols to simulate noisy channel
            for(int f = 0; f < 0/*(symSize/1.75)*/; f++) {
                int delId = std::rand()%symStore.size();
                symStore.erase(symStore.begin() + delId);
                if(logEnable) {
                    std::cout << delId << "\t" << "Total symbols are " << symStore.size() << "\n";
                }
            }
            
            readVaultBox(key_c, key_c, key_c, r_vaultBox, symStore);
            
            if(logEnable) {
                std::cout << "\n";
                PrintKeyAndIV(ekey, iv, akey);
                for(std::string p_this: vaultBox) { std::cout << p_this << "\n"; }
                std::cout << "\n";
            }
            
            iota(r_indexes.begin(), r_indexes.end(), 0);
            std::mt19937 mtGen(num_ranDev2);
            shuffle(r_indexes.begin(), r_indexes.end(), mtGen);
            //decryptAES_GCM_AEAD(ekey, iv, idxCnt);
            //decryptChaChaPoly(ekey, iv, idxCnt);
            
            decryptVaultBox(ekey2, iv2, akey2, indexCount, prevSeq, prevAlert,
                            r_vaultBox, r_indexes, ekeyMaster, akeyMaster);
            
            
            // Forward-secure XOR key
            CryptoPP::SHA256 hash;
            hash.Update((const CryptoPP::byte*)pass_c.data(), pass_c.size());
            pass_c.resize(hash.DigestSize());
            hash.Final((CryptoPP::byte*)&pass_c[0]);
            //pass_c = pass_c.substr(0, pass_c.length()/2);
	    pass_c.resize(pass_c.length()/2);
            password = pass_c;
        }
        
        return 0;
    }
    
    catch(CryptoPP::BufferedTransformation::NoChannelSupport& e) {
        std::cerr << "Caught NoChannelSupport..." << "\n";
        std::cerr << e.what() << "\n";
        exit(1);
    }
    
    catch(CryptoPP::AuthenticatedSymmetricCipher::BadState& e) {
        std::cerr << "Caught BadState..." << "\n";
        std::cerr << e.what() << "\n";
        exit(1);
    }
    
    catch(CryptoPP::InvalidArgument& e) {
        std::cerr << "Caught InvalidArgument..." << "\n";
        std::cerr << e.what() << "\n";
        exit(1);
    }
    
    catch(const CryptoPP::Exception& e) {
        std::cerr << e.what() << "\n";
        exit(1);
    }
    
    catch(std::bad_alloc& ba){
        std::cerr << "bad_alloc caught: " << ba.what() << "\n";
        exit(1);
    }
    
    catch(std::exception& e) {
        std::cerr << e.what() << "\n";
        exit(1);
    }
}
