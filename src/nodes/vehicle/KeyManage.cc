/*
 * KeyMg.cc
 *
 *  Created on: Jun 13, 2023
 *      Author: puyijun
 */

#include "nodes/vehicle/KeyManage.h"

#include "baseAppl/ApplToPhyControlInfo.h"
#include "MIXIM_veins/nic/phy/PhyToMacControlInfo.h"
#include "MIXIM_veins/nic/phy/decider/DeciderResult80211.h"


namespace VENTOS {

Define_Module(VENTOS::ApplVKeyManage);

#define  SEND_DELAY_OFFSET  0.1

ApplVKeyManage::~ApplVKeyManage()
{
    EVP_cleanup();
}

void ApplVKeyManage::initialize(int stage)
{
    super::initialize(stage);

    if (stage == 0)
    {
        grouKeyEnabled = par("grouKeyEnabled").boolValue();

        // subscribe memberChangeSignal
        getSimulation()->getSystemModule()->subscribe("memberChangeSignal", this);
        getSimulation()->getSystemModule()->subscribe("newLeaderSignal", this);

        OpenSSL_add_all_algorithms();
        // if i am leader, play GKM
        // generate sm2 key, send
        if(myPlnDepth == 0)
        {
            if(generateSM4Key())
            {
                sendKeyMsg("multicast", CERT_REQ, myPlnID);
            }
        }
    }
}


void ApplVKeyManage::finish()
{
    super::finish();

    // unsubscribe memberChangeSignal
    if(getSimulation()->getSystemModule()->isSubscribed("memberChangeSignal", this))
    {
        getSimulation()->getSystemModule()->unsubscribe("memberChangeSignal", this);
    }
    if(getSimulation()->getSystemModule()->isSubscribed("newLeaderSignal", this))
    {
        getSimulation()->getSystemModule()->unsubscribe("newLeaderSignal", this);
    }
}


void ApplVKeyManage::handleSelfMsg(omnetpp::cMessage* msg)
{
    super::handleSelfMsg(msg);
}


void ApplVKeyManage::onBeaconVehicle(BeaconVehicle* wsm)
{
    // pass it down!
    super::onBeaconVehicle(wsm);

}

void ApplVKeyManage::receiveSignal(omnetpp::cComponent *source, omnetpp::simsignal_t signalID, omnetpp::cObject *obj, omnetpp::cObject *details)
{
    StringPacket *packet = dynamic_cast<StringPacket *>(obj);
    std::string senderSUMOID;
    if (packet != nullptr)
        senderSUMOID = packet->getString();
    else
        throw omnetpp::cRuntimeError("Wrong signal value");

    if(signalID == memberChangeSignal && senderSUMOID == SUMOID)
    {
        LOG_WARNING << boost::format("%s: front leader change key...\n")
                % SUMOID << std::flush;
        if(generateSM4Key())
        {
            sendKeyMsg("multicast", CERT_REQ, myPlnID);
        }
    }
    else if(signalID == newLeaderSignal && senderSUMOID == SUMOID)
    {
        LOG_WARNING << boost::format("%s: back leader generate key...\n")
                        % SUMOID << std::flush;
        if(generateSM4Key())
        {
            sendKeyMsg("multicast", CERT_REQ, myPlnID);
        }
    }
}


void ApplVKeyManage::onBeaconRSU(BeaconRSU* wsm)
{
    // pass it down!
    super::onBeaconRSU(wsm);
}


void ApplVKeyManage::onKeyMsg(KeyMsg *wsm)
{
    /* followers, send CERT_MSG to leader */
    if(wsm->getUCommandType() == CERT_REQ && wsm->getSenderID() == myPlnID)
    {
        BIO* bio = BIO_new(BIO_s_file());
        std::string directory = "/home/puyijun/dev3/VENTOS/examples/intersectionPlatoon/crypto/";
        std::string folder = SUMOID;
        std::string fullPath = directory + folder + "/certificate.crt";
//        LOG_INFO << boost::format("%s certificate location: %s\n")% SUMOID % fullPath << std::flush;
        std::string certificateStr = ReadCertificateToString(fullPath);

        value_k value;
        value.cert = certificateStr;
        sendKeyMsg(myPlnID, CERT_MSG, myPlnID, value);
        LOG_INFO << boost::format("%s send CERT_MSG to %s\n")% SUMOID % myPlnID << std::flush;
    }

    /* leader receive certificate from followers, 1.verify it and 2.use pub key to encrypt sm4 key*/
    if(wsm->getUCommandType() == CERT_MSG && wsm->getReceiverID() == SUMOID)
    {
        std::string certificateStr = wsm->getValue().cert;

        // test
//        std::string testStr = "123456";
//        std::string testEncrypt = encryptWithSM2PublicKey(certificateStr, testStr);
//        std::string path = "/home/puyijun/dev3/VENTOS/examples/intersectionPlatoon/crypto/veh/private.key";
//        std::string testDecrypt = decryptWithSM2PrivateKey(path, testEncrypt);
//        LOG_INFO << boost::format("e::: %s\nd::: %s\n") % testEncrypt % testDecrypt << std::flush;

        std::string sender = wsm->getSenderID();
        std::string caCertFilePath = "/home/puyijun/dev3/VENTOS/examples/intersectionPlatoon/crypto/GKM/ca_certificate.crt";
        // verify
        bool isCertValid  = verifyCert(certificateStr, caCertFilePath);
        if(isCertValid)
        {
            // encrypt and send
            LOG_INFO << boost::format("verified\n") << std::flush;
            std::string encryptKey = encryptSM4Key(certificateStr);
            value_k value;
            value.encryptSM4Key = encryptKey;
            sendKeyMsg(sender, ENCRYPT_KEY, myPlnID, value);
        }
    }

    /* follower receive encrypt key, decrypt and use it to communicate*/
    if(wsm->getUCommandType() == ENCRYPT_KEY && wsm->getReceiverID() == SUMOID) //multicast from leaderGKM
    {
        LOG_INFO << boost::format("%s received sm4 key\n")% SUMOID << std::flush;

        std::string ciphertext = wsm->getValue().encryptSM4Key;
        std::string privateKeyPath = "/home/puyijun/dev3/VENTOS/examples/intersectionPlatoon/crypto/" + SUMOID + "/private.key";
        std::string encodedSM4Key = decryptSM4Key(privateKeyPath, ciphertext);

        LOG_INFO << boost::format("%s SM4 key(32): %s\n")% SUMOID % encodedSM4Key << std::flush;
    }

    if(wsm->getUCommandType() == KEY_DELETE && wsm->getSenderID() == myPlnID) //multicast from leaderleaderGKM
    {
        // followers, delete key
        // ...
    }

    if(wsm->getUCommandType() == DEL_ACK && wsm->getReceiverID() == SUMOID) //unicast for from followers
    {
        // leader, send REV_REQ to GKM
    }
}

void ApplVKeyManage::sendKeyMsg(std::string receiverID, uCommand_k msgType, std::string receivingPlatoonID, value_k value)
{
    if(plnMode != platoonManagement)
        throw omnetpp::cRuntimeError("This application mode does not support platoon management!");

    KeyMsg* wsm = new KeyMsg("KeyMsg", TYPE_KEY_MESSAGE);

    // add header length
    wsm->addBitLength(headerLength);

    // add payload length
    wsm->addBitLength(dataLengthBits);

    wsm->setWsmVersion(1);
    wsm->setSecurityType(1);
    wsm->setChannelNumber(Veins::Channels::CCH);
    wsm->setDataRate(1);
    wsm->setPriority(dataPriority);
    wsm->setPsid(0);

    wsm->setSenderID(SUMOID.c_str());
    wsm->setReceiverID(receiverID.c_str());
    wsm->setUCommandType(msgType);
    wsm->setSendingPlatoonID(myPlnID.c_str());
    wsm->setReceivingPlatoonID(receivingPlatoonID.c_str());
    wsm->setValue(value);

    sendDelayed(wsm, uniform(0,SEND_DELAY_OFFSET), lowerLayerOut);
}


bool ApplVKeyManage::generateSM4Key()
{
    sm4Key.resize(SM4_KEY_LENGTH);
    if (RAND_bytes(sm4Key.data(), SM4_KEY_LENGTH) != 1) {
        throw std::runtime_error("Failed to generate SM4 key");
    }
    return true;
}

std::string ApplVKeyManage::encodeSM4Key()
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < sm4Key.size(); ++i) {
        ss << std::setw(2) << static_cast<int>(sm4Key[i]);
    }
    return ss.str();
}

void ApplVKeyManage::decodeSM4Key(const std::string& encodedKey)
{
    if (encodedKey.length() % 2 != 0) {
        throw std::runtime_error("Invalid encoded SM4 key length");
    }

    size_t keyLength = encodedKey.length() / 2;
    sm4Key.reserve(keyLength);

    for (size_t i = 0; i < keyLength; ++i) {
        std::string byteString = encodedKey.substr(i * 2, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        sm4Key.push_back(byte);
    }
}

std::string ApplVKeyManage::ReadCertificateToString(const std::string &certificatePath)
{
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

    return result;
}

bool ApplVKeyManage::verifyCert(const std::string &certificateString, const std::string &caCertFilePath)
{
    // Load certificate from string
    BIO* bio = BIO_new_mem_buf(certificateString.data(), certificateString.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO");
    }

    X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!certificate) {
        throw std::runtime_error("Failed to read certificate from string");
    }

    // Load CA certificate
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        throw std::runtime_error("Failed to create X509 store");
    }

    if (X509_STORE_load_locations(store, caCertFilePath.c_str(), nullptr) != 1) {
        X509_STORE_free(store);
        throw std::runtime_error("Failed to load CA certificate");
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_STORE_free(store);
        throw std::runtime_error("Failed to create X509_STORE_CTX");
    }

    if (X509_STORE_CTX_init(ctx, store, certificate, nullptr) != 1) {
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        throw std::runtime_error("Failed to initialize X509_STORE_CTX");
    }

    // Verify certificate
    int result = X509_verify_cert(ctx);
    bool verified = (result == 1);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return verified;
}

std::string ApplVKeyManage::encryptSM4Key(const std::string& sm2CertificateString)
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

    // verify public key
//    int keyType = EVP_PKEY_id(publicKey);
//    if (keyType != EVP_PKEY_SM2) {
//        throw std::runtime_error("keyType wrong");
//    }

//    EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(publicKey);
//    const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
//    if (!EC_GROUP_cmp(ecGroup, EC_GROUP_new_by_curve_name(NID_sm2))) {
//        throw std::runtime_error("param not match");
//    }

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
    std::string plaintext = encodeSM4Key();
    size_t plaintextLen = plaintext.size();
    LOG_INFO << boost::format("%s SM4 key(%d): %s\n")% SUMOID %plaintextLen % plaintext << std::flush;
    size_t ciphertextLen = plaintextLen + EVP_PKEY_size(publicKey);
//    LOG_INFO << boost::format("%s SM4 key(%d): %s\nciphertextLen:%d")% SUMOID %plaintextLen % plaintext %ciphertextLen << std::flush;
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


std::string ApplVKeyManage::decryptSM4Key(std::string privateKeyFile, const std::string& ciphertext)
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

    // set private variable sm4Key
    decodeSM4Key(result);
    // result is encoded(32)
    return result;
}

}
