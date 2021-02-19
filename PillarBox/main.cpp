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

int writeVaultBox(string alert); //returns operation status
int readVaultBox(); //returns number of valid messages

vector<string> vaultBox;

mt19937 mtGen(101);
uniform_int_distribution<int> uniDist(0, 1023);

int main(int argc, const char * argv[]) {
    
    /*
    
    char secureAlerts [1024][1024];
    for(int i=0; i<1024; i++) {
        std::string alertText = "This is string number ";
        alertText += to_string(i);
        strncpy(secureAlerts[i], alertText.c_str(), 1023);
        cout << secureAlerts[i] << endl;
    }
     
    unsigned seed = static_cast<int> (chrono::system_clock::now().time_since_epoch().count());
    mt19937 mtGen(seed);
     
    random_device ranDev;
    mt19937 mtGen(ranDev());
     
    */
    
    for(int i=0; i<1024; i++) {
        vaultBox.push_back("it is the default string");
    }
    
    for(int i=0; i<100; i++) {
        std::string alertText = "This is string number ";
        alertText += to_string(i);
        writeVaultBox(alertText);
    }
    
    /*
    cout << vaultBox[rand()%1024] << endl;
    cout << vaultBox[rand()%1024] << endl;
    cout << vaultBox[rand()%1024] << endl;
    vaultBox[100] = "100";
    cout << vaultBox[100] << endl;
    */
    
    readVaultBox();
    
    return 0;
}

int writeVaultBox(string alert) {
    int i=0;
    
    for (int i=0; i<4; i++) {
        vaultBox[uniDist(mtGen)] = alert;
    }
    
    return i;
}

int readVaultBox() {
    int i=0;
    
    for(int i=0; i<1024; i++) {
        cout << vaultBox[i] << endl;
    }
    
    return i;
}
