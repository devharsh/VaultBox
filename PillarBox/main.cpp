//
//  main.cpp
//  PillarBox
//
//  Created by Devharsh Trivedi on 2/17/21.
//

#include <iostream>
#include <string>
#include <vector>
#include <random>
//#include <chrono>

using namespace std;

int main(int argc, const char * argv[]) {
    
    /*
    char secureAlerts [1024][1024];
    for(int i=0; i<1024; i++) {
        std::string alertText = "This is string number ";
        alertText += to_string(i);
        strncpy(secureAlerts[i], alertText.c_str(), 1023);
        cout << secureAlerts[i] << endl;
    }
    */
    
    vector<string> secureAlerts;
    for(int i=0; i<1024; i++) {
        std::string alertText = "This is string number ";
        alertText += to_string(i);
        secureAlerts.push_back(alertText);
        //cout << secureAlerts[i] << endl;
    }
    
    //unsigned seed = static_cast<int> (chrono::system_clock::now().time_since_epoch().count());
    //mt19937 generator(seed);
    
    //random_device ranDev;
    //mt19937 mtGen(ranDev());
    
    mt19937 mtGen(101);
    uniform_int_distribution<int> uniDist(0, 1023);
    for (int i=0; i<4; i++) {
        cout << uniDist(mtGen) << "\t";
    }
    cout << endl;
    
    return 0;
}
