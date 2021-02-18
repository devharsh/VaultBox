//
//  main.cpp
//  PillarBox
//
//  Created by Devharsh Trivedi on 2/17/21.
//

#include <iostream>
#include <string>
#include <vector>

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
        cout << secureAlerts[i] << endl;
    }
    
    return 0;
}
