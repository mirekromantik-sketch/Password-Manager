#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <random>
#include <algorithm>

#include <sodium.h>
#include "json.hpp"

using json = nlohmann::json;
using namespace std;

/* ---------------- PASSWORD GENERATOR ---------------- */

string generatePassword(int length) {
    const string lower = "abcdefghijklmnopqrstuvwxyz";
    const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const string numbers = "0123456789";
    const string symbols = "!@#$%^&*()_=+{}[];':|<>/";

    string all = lower + upper + numbers + symbols;

    static thread_local mt19937 rng(random_device{}());
    uniform_int_distribution<size_t> dist(0, all.size() - 1);

    string pwd;
    pwd.reserve(length);

    pwd += lower[rng() % lower.size()];
    pwd += upper[rng() % upper.size()];
    pwd += numbers[rng() % numbers.size()];
    pwd += symbols[rng() % symbols.size()];

    for (int i = 4; i < length; ++i)
        pwd += all[dist(rng)];

    shuffle(pwd.begin(), pwd.end(), rng);
    return pwd;
}

/* ---------------- CRYPTO ---------------- */

vector<unsigned char> deriveKey(
    const string& master,
    const unsigned char* salt
) {
    vector<unsigned char> key(
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    );

    if (crypto_pwhash(
        key.data(), key.size(),
        master.c_str(), master.size(),
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) {
        throw runtime_error("Key derivation failed");
    }

    return key;
}

vector<unsigned char> encryptData(
    const string& plaintext,
    const vector<unsigned char>& key,
    unsigned char* nonce
) {
    vector<unsigned char> ciphertext(
        plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES
    );

    unsigned long long len;
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &len,
        (const unsigned char*)plaintext.data(), plaintext.size(),
        nullptr, 0, nullptr,
        nonce, key.data()
    );

    ciphertext.resize(len);
    return ciphertext;
}

string decryptData(
    const vector<unsigned char>& ciphertext,
    const vector<unsigned char>& key,
    const unsigned char* nonce
) {
    vector<unsigned char> plaintext(
        ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES
    );

    unsigned long long len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &len,
        nullptr,
        ciphertext.data(), ciphertext.size(),
        nullptr, 0,
        nonce, key.data()
    ) != 0) {
        throw runtime_error("Wrong password or corrupted vault");
    }

    return string(plaintext.begin(), plaintext.begin() + len);
}

/* ---------------- VAULT I/O ---------------- */

void writeVault(
    const string& filename,
    const unsigned char* salt,
    const unsigned char* nonce,
    const vector<unsigned char>& data
) {
    ofstream f(filename, ios::binary | ios::trunc);
    f.write((char*)salt, crypto_pwhash_SALTBYTES);
    f.write((char*)nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    f.write((char*)data.data(), data.size());
}

bool readVault(
    const string& filename,
    unsigned char* salt,
    unsigned char* nonce,
    vector<unsigned char>& data
) {
    ifstream f(filename, ios::binary);
    if (!f) return false;

    f.read((char*)salt, crypto_pwhash_SALTBYTES);
    f.read((char*)nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    data.assign(
        istreambuf_iterator<char>(f),
        istreambuf_iterator<char>()
    );
    return true;
}

/* ---------------- MAIN ---------------- */

int main() {
    if (sodium_init() < 0) {
        cerr << "libsodium init failed\n";
        return 1;
    }

    cout << "1. Create / add passwords\n";
    cout << "2. Open vault\n";
    cout << "Choose: ";

    int choice;
    cin >> choice;
    cin.ignore();

    if (choice == 1) {
        int groups, len;
        cout << "Groups: "; cin >> groups;
        cout << "Length per group: "; cin >> len;
        cin.ignore();

        json vault = json::array();

        for (int i = 0; i < groups; ++i) {
            time_t now = time(nullptr);
            vault.push_back({
                {"haslo", generatePassword(len)},
                {"timestamp", ctime(&now)}
            });
        }

        string master;
        cout << "Master password: ";
        getline(cin, master);

        unsigned char salt[crypto_pwhash_SALTBYTES];
        unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        randombytes_buf(salt, sizeof salt);

        auto key = deriveKey(master, salt);
        auto encrypted = encryptData(vault.dump(4), key, nonce);

        writeVault("Hasla.vault", salt, nonce, encrypted);
        cout << "Vault encrypted and saved.\n";
    }

    else if (choice == 2) {
        unsigned char salt[crypto_pwhash_SALTBYTES];
        unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        vector<unsigned char> ciphertext;

        if (!readVault("Hasla.vault", salt, nonce, ciphertext)) {
            cerr << "Vault not found\n";
            return 1;
        }

        string master;
        cout << "Master password: ";
        getline(cin, master);

        auto key = deriveKey(master, salt);
        string plaintext = decryptData(ciphertext, key, nonce);

        json vault = json::parse(plaintext);
        for (auto& e : vault) {
            cout << e["haslo"] << " | " << e["timestamp"];
        }
    }

    return 0;
}
