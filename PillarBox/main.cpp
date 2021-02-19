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

using namespace std;

#define redundancyFactor 4
#define bufferSize 256
#define maxAlerts (redundancyFactor * bufferSize)

int writeVaultBox(string alert);
void readVaultBox();
void shuffleIndexes();

vector<string> vaultBox;
vector<int> indexes;

int totalAlertCount = 0;
int indexCount = 0;

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
     
    cout << vaultBox[rand()%1024] << endl;
    cout << vaultBox[rand()%1024] << endl;
    cout << vaultBox[rand()%1024] << endl;
    vaultBox[100] = "100";
    cout << vaultBox[100] << endl;
     
    */
    
    for(int i=0; i<maxAlerts; i++) {
        indexes.push_back(i);
        vaultBox.push_back("it is the default string");
    }
    
    shuffleIndexes();
    
    for(int i=0; i<100; i++) {
        std::string alertText = "This is string number ";
        alertText += to_string(i);
        writeVaultBox(alertText);
    }
    
    readVaultBox();
    
    return 0;
}

int writeVaultBox(string alert) {
    indexCount = indexCount % maxAlerts;
    
    for (int i=0; i<redundancyFactor; i++) {
        vaultBox[indexes[indexCount]] = alert;
        indexCount++;
        totalAlertCount++;
    }
    
    return totalAlertCount;
}

void readVaultBox() {
    for(int i=0; i<maxAlerts; i++) {
        cout << vaultBox[i] << endl;
    }
}

void shuffleIndexes() {
    random_device ranDev;
    mt19937 mtGen(ranDev());
    shuffle(indexes.begin(), indexes.end(), mtGen);
}
