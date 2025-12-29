#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <sodium.h>
#include "json.hpp"

using json = nlohmann::json;
using namespace std;

vector<unsigned char> deriveKey(
    const string& masterPassword,
    const unsigned char* salt
) {
    vector<unsigned char> key(
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    );

    if (crypto_pwhash(
        key.data(),
        key.size(),
        masterPassword.c_str(),
        masterPassword.size(),
        salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_DEFAULT
    ) != 0) {
        throw runtime_error("Key derivation failed");
    }

    return key;
}

int main() {
    if (sodium_init() < 0) {
        cerr << "libsodium init failed\n";
        return 1;
    }

    ifstream file("Hasla.vault", ios::binary);
    if (!file) {
        cerr << "Cannot open vault file\n";
        return 1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    file.read(reinterpret_cast<char*>(salt), sizeof salt);
    file.read(reinterpret_cast<char*>(nonce), sizeof nonce);

    vector<unsigned char> ciphertext(
        (istreambuf_iterator<char>(file)),
        istreambuf_iterator<char>()
    );

    file.close();

    string masterPassword;
    cout << "Enter master password: ";
    getline(cin, masterPassword);

    auto key = deriveKey(masterPassword, salt);

    vector<unsigned char> plaintext(
        ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES
    );

    unsigned long long plaintextLen;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(),
        &plaintextLen,
        nullptr,
        ciphertext.data(),
        ciphertext.size(),
        nullptr,
        0,
        nonce,
        key.data()
    ) != 0) {
        cerr << "Decryption failed (wrong password or corrupted file)\n";
        return 1;
    }

    string jsonText(
        plaintext.begin(),
        plaintext.begin() + plaintextLen
    );

    json vault = json::parse(jsonText);

    cout << "\n=== STORED PASSWORDS ===\n";
    for (const auto& entry : vault) {
        cout << "Password: " << entry["haslo"] << "\n";
        cout << "Time: " << entry["timestamp"] << "\n\n";
    }

    getchar();
    return 0;
}
