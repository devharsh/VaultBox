//
//  main.cpp
//  VaultBox
//
//  Created by Devharsh Trivedi on 3/11/21.
//

#include <iostream>
#include <iomanip>
#include <string>
#include <map>
#include <random>
#include <cmath>
#include <vector>

int main(int argc, const char * argv[]) {
    std::random_device ranDev;
    unsigned int num_ranDev = ranDev();
    std::cout << num_ranDev << std::endl;
    std::mt19937 mtGen(num_ranDev);
    std::vector<unsigned long> indexes(10);
    
    iota(indexes.begin(), indexes.end(), 0);
    for(int i=0; i<10; i++) {
        std::cout << indexes[i] << "\t";
    }
    std::cout << std::endl;
    
    shuffle(indexes.begin(), indexes.end(), std::default_random_engine(num_ranDev));
    for(int i=0; i<10; i++) {
        std::cout << indexes[i] << "\t";
    }
    std::cout << std::endl;
    
    iota(indexes.begin(), indexes.end(), 0);
    for(int i=0; i<10; i++) {
        std::cout << indexes[i] << "\t";
    }
    std::cout << std::endl;
    
    shuffle(indexes.begin(), indexes.end(), std::default_random_engine(num_ranDev));
    for(int i=0; i<10; i++) {
        std::cout << indexes[i] << "\t";
    }
    std::cout << std::endl;
    
    iota(indexes.begin(), indexes.end(), 0);
    for(int i=0; i<10; i++) {
        std::cout << indexes[i] << "\t";
    }
    std::cout << std::endl;
    
    shuffle(indexes.begin(), indexes.end(), mtGen);
    for(int i=0; i<10; i++) {
        std::cout << indexes[i] << "\t";
    }
    std::cout << std::endl;
    
    iota(indexes.begin(), indexes.end(), 0);
    for(int i=0; i<10; i++) {
        std::cout << indexes[i] << "\t";
    }
    std::cout << std::endl;
    
    shuffle(indexes.begin(), indexes.end(), mtGen);
    for(int i=0; i<10; i++) {
        std::cout << indexes[i] << "\t";
    }
    std::cout << std::endl;
    
    return 0;
}
