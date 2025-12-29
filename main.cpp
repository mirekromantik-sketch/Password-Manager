#include <iostream>
#include <cstdlib>
#include <ctime>
#include <cctype>
#include <fstream>
#include <filesystem>
#include <string>
#include <random>
#include <algorithm>
#include "json.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;
using namespace std;

int groups;
int groupLength;

string generatePassword(int length) {
    const string lower = "abcdefghijklmnopqrstuwvxyz";
    const string upper = "ABCDEFGHIJKLMNOPQRSTUWVXYZ";
    const string number = "0123456789";
    const string symbol = "!@#$%^&*()_=+{}[];':|<>/";
    string all = lower + upper + number + symbol;

    static thread_local mt19937 rng(random_device{}());
    uniform_int_distribution<size_t> dist(0, all.size() - 1);

    string password;
    password.reserve(length);

    if (length >= 4) {
        uniform_int_distribution<size_t> dL(0, lower.size() - 1);
        uniform_int_distribution<size_t> dU(0, upper.size() - 1);
        uniform_int_distribution<size_t> dN(0, number.size() - 1);
        uniform_int_distribution<size_t> dS(0, symbol.size() - 1);

        password += lower[dL(rng)];
        password += upper[dU(rng)];
        password += number[dN(rng)];
        password += symbol[dS(rng)];

        for (int i = 4; i < length; ++i)
            password += all[dist(rng)];
    } else {
        for (int i = 0; i < length; ++i)
            password += all[dist(rng)];
    }

    shuffle(password.begin(), password.end(), rng);

    return password;
}

string generateFormattedPassword(int groups, int grouplength){
    string password;
    for (int i = 0; i < groups; ++i) {
        if (i > 0) 
            password += '-';
        password += generatePassword(grouplength);
    }
    return password;
}

int main() {
    char answer;
    while(true) {
        cout << "Wprowadz liczbe grup: ";
        cin >> groups;

        if (groups < 1) {
            cout << "Grupy musza byc wieksze lub rowne 1" << endl;                
            continue;
        }

        cout << "Wprowadz liczbe znakow w grupie: ";
        cin >> groupLength;

        if (groupLength < 1) {
            cout << "Dlugosc grupy musi byc wieksza niz 0" << endl;                
            continue;
        }
        
        string password = generateFormattedPassword(groups, groupLength);

        json j;
        ifstream inputfile("hasla.json");
        if (inputfile) {
            inputfile >> j;
            inputfile.close();
        }

        time_t now = time(nullptr);
        j.push_back({
            {"haslo", password},
            {"timestamp", ctime(&now)}
        });

        ofstream outputfile("hasla.json", ios::app);
        if (!outputfile) {
            cerr << "problem" << endl;
        } else {
            outputfile << j.dump(4);
            outputfile.close();
        }

        cout << "Czy wygenerowac wiecej hasel? y/n" << endl;
        cin >> answer;

        if (answer == 'y' || answer == 'Y') {
            continue;
        } else {
            break;
        }
    }

    system("start hasla.json");

    return 0;
}
