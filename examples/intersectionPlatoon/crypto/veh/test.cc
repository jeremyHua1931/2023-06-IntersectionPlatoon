#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <stddef.h>
#include <string>
#include <stdexcept>
#include <vector>
#include <iostream>

using namespace std;

std::string encryptSM4Key(const std::string& sm2CertificateString)
{
    // get certificate
    BIO* bio = BIO_new_mem_buf(sm2CertificateString.data(), sm2CertificateString.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO");
    }

    X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!certificate) {
        throw std::runtime_error("Failed to read certificate from string");
    }

    // get public key
    EVP_PKEY* publicKey = X509_get_pubkey(certificate);
    if (!publicKey) {
        X509_free(certificate);
        throw std::runtime_error("Failed to extract public key from certificate");
    }

    EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(publicKey);
    if (!ecKey) {
        EVP_PKEY_free(publicKey);
        X509_free(certificate);
        throw std::runtime_error("Failed to extract EC key from public key");
    }

    if (EC_KEY_check_key(ecKey) != 1) {
        EVP_PKEY_free(publicKey);
        X509_free(certificate);
        throw std::runtime_error("Invalid EC key");
    }

    // create context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(publicKey);
        X509_free(certificate);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        X509_free(certificate);
        throw std::runtime_error("Failed to initialize encryption");
    }
    std::string plaintext = "123456";
    size_t plaintextLen = plaintext.size();
//    LOG_INFO << boost::format("%s SM4 key(%d): %s\n")% SUMOID %plaintextLen % plaintext << std::flush;
    size_t ciphertextLen = 0;
    // std::cout << "ciphertextLen" <<plaintextLen % plaintext %ciphertextLen << std::flush;
   if (EVP_PKEY_encrypt(ctx, nullptr, &ciphertextLen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintextLen) <= 0) {
       EVP_PKEY_CTX_free(ctx);
       EVP_PKEY_free(publicKey);
       X509_free(certificate);
       throw std::runtime_error("Failed to determine ciphertext length");
   }

    std::vector<unsigned char> ciphertext(ciphertextLen);
    if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &ciphertextLen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintextLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        X509_free(certificate);
        throw std::runtime_error("Failed to encrypt plaintext");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(publicKey);
    X509_free(certificate);

    std::string result(reinterpret_cast<char*>(ciphertext.data()), ciphertextLen);
    return result;
}


std::string decryptSM4Key(std::string privateKeyFile, const std::string& ciphertext)
{
    // load private key from file
    BIO* keyBio = BIO_new_file(privateKeyFile.c_str(), "r");
    if (!keyBio) {
        throw std::runtime_error("Failed to open private key file");
    }

    EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    if (!privateKey) {
        BIO_free(keyBio);
        throw std::runtime_error("Failed to read private key");
    }

    // create context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to initialize decryption");
    }

    size_t ciphertextLen = ciphertext.size();
    size_t plaintextLen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &plaintextLen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertextLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to determine plaintext length");
    }

    std::vector<unsigned char> plaintext(plaintextLen);
    if (EVP_PKEY_decrypt(ctx, plaintext.data(), &plaintextLen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertextLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        throw std::runtime_error("Failed to decrypt ciphertext");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privateKey);

    std::string result(reinterpret_cast<char*>(plaintext.data()), plaintextLen);

    // result is encoded(32)
    return result;
}

int main()
{
    std::cout << "this is main" << std::endl;
    std::string certificatePath = "/home/puyijun/dev3/VENTOS/examples/intersectionPlatoon/crypto/veh//certificate.crt";
    FILE* file = fopen(certificatePath.c_str(), "r");
    if (!file) {
        throw std::runtime_error("Failed to open certificate file");
    }

    X509* certificate = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (!certificate) {
        throw std::runtime_error("Failed to read certificate");
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        X509_free(certificate);
        throw std::runtime_error("Failed to create BIO");
    }

    if (PEM_write_bio_X509(bio, certificate) != 1) {
        BIO_free(bio);
        X509_free(certificate);
        throw std::runtime_error("Failed to write certificate to BIO");
    }

    char* buffer = nullptr;
    long size = BIO_get_mem_data(bio, &buffer);
    std::string result(buffer, size);

    BIO_free(bio);
    X509_free(certificate);
    
    // *******************************************
    std::string encodedKey = encryptSM4Key(result);
    std::cout << "encodedKey: " << encodedKey << std::endl;
    return 0;
}

