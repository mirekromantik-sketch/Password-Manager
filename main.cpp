#include <iostream>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <string>
#include <random>
#include <algorithm>
#include <vector>
#include "json.hpp"
#include <sodium.h>

using json = nlohmann::json;
using namespace std;

// Global variables
int groups;
int groupLength;

// ---------------- PASSWORD GENERATOR ----------------
string generatePassword(int length) {
    const string lower = "abcdefghijklmnopqrstuvwxyz";
    const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const string numbers = "0123456789";
    const string symbols = "!@#$%^&*()_=+{}[];':|<>/";

    string all = lower + upper + numbers + symbols;

    static thread_local mt19937 rng(random_device{}());
    uniform_int_distribution<size_t> dist(0, all.size() - 1);

    string password;
    password.reserve(length);

    if (length >= 4) {
        uniform_int_distribution<size_t> dl(0, lower.size() - 1);
        uniform_int_distribution<size_t> du(0, upper.size() - 1);
        uniform_int_distribution<size_t> dn(0, numbers.size() - 1);
        uniform_int_distribution<size_t> ds(0, symbols.size() - 1);

        password += lower[dl(rng)];
        password += upper[du(rng)];
        password += numbers[dn(rng)];
        password += symbols[ds(rng)];

        for (int i = 4; i < length; ++i)
            password += all[dist(rng)];
    } else {
        for (int i = 0; i < length; ++i)
            password += all[dist(rng)];
    }

    shuffle(password.begin(), password.end(), rng);
    return password;
}

string generateFormattedPassword(int groups, int groupLength) {
    string password;
    for (int i = 0; i < groups; ++i) {
        if (i > 0) password += '-';
        password += generatePassword(groupLength);
    }
    return password;
}

// ---------------- CRYPTO FUNCTIONS ----------------
vector<unsigned char> deriveKey(const string& masterPassword, const unsigned char* salt) {
    vector<unsigned char> key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    if (crypto_pwhash(
            key.data(),
            key.size(),
            masterPassword.c_str(),
            masterPassword.size(),
            salt,
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE,
            crypto_pwhash_ALG_DEFAULT) != 0) {
        cerr << "Key derivation failed\n";
        exit(1);
    }

    return key;
}

vector<unsigned char> encryptData(const string& plaintext,
                                  const vector<unsigned char>& key,
                                  unsigned char* nonce) {
    vector<unsigned char> ciphertext(
        plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES
    );

    unsigned long long cipherLen;
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(),
        &cipherLen,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        plaintext.size(),
        nullptr, // additional data
        0,
        nullptr, // nsec
        nonce,
        key.data()
    );

    ciphertext.resize(cipherLen);
    return ciphertext;
}

void writeVault(const string& filename,
                const unsigned char* salt,
                const unsigned char* nonce,
                const vector<unsigned char>& ciphertext) {
    ofstream file(filename, ios::binary | ios::trunc);
    file.write((char*)salt, crypto_pwhash_SALTBYTES);
    file.write((char*)nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    file.write((char*)ciphertext.data(), ciphertext.size());
    file.close();
}

// ---------------- MAIN ----------------
int main() {
    if (sodium_init() < 0) {
        cerr << "libsodium init failed\n";
        return 1;
    }

    char answer;
    vector<json> vault;

    while (true) {
        cout << "Wprowadz liczbe grup: ";
        cin >> groups;
        if (groups < 1) {
            cout << "Grupy musza byc wieksze lub rowne 1\n";
            continue;
        }

        cout << "Wprowadz liczbe znakow w grupie: ";
        cin >> groupLength;
        if (groupLength < 1) {
            cout << "Dlugosc grupy musi byc wieksza niz 0\n";
            continue;
        }

        string password = generateFormattedPassword(groups, groupLength);
        time_t now = time(nullptr);

        vault.push_back({
            {"haslo", password},
            {"timestamp", ctime(&now)}
        });

        cout << "Czy wygenerowac wiecej hasel? y/n\n";
        cin >> answer;
        if (answer == 'y' || answer == 'Y') continue;
        else break;
    }

    // ---------------- ENCRYPT AND SAVE ----------------
    string jsonData = json(vault).dump(4);

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(salt, sizeof(salt));

    string masterPassword;
    cout << "Podaj haslo glowne do zaszyfrowania: ";
    cin >> masterPassword;

    vector<unsigned char> key = deriveKey(masterPassword, salt);
    vector<unsigned char> encrypted = encryptData(jsonData, key, nonce);

    writeVault("Hasla.vault", salt, nonce, encrypted);

    cout << "Hasla zapisane i zaszyfrowane w Hasla.vault\n";

    return 0;
}
