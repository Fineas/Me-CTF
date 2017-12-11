#include <bits/stdc++.h>

using namespace std;

int main (){
    char filename[100];
    char programname[100];
    char payload[100];

    cout << "Enter file name to compile: ";
    cin.getline(filename, 100);

    cout << "Enter a name for the program: ";
    cin.getline(programname, 100);

    payload = "g++ -std=c++11 ";
    strcat(payload, filename);
    strcat(payload, " -o ");
    strcat(payload, programname);

    /// Compile The File using -std=c++11
    system(payload);

    /// Run the program
    cout << "\nRunning file...";
    payoad = "./";
    strncat(payload, programname);
    system(payload);

    return 0;
}
