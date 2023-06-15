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
            if(generateSM4Key(sm4Key))
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
        if(generateSM4Key(sm4Key))
        {
            sendKeyMsg("multicast", CERT_REQ, myPlnID);
        }
    }
    else if(signalID == newLeaderSignal && senderSUMOID == SUMOID)
    {
        LOG_WARNING << boost::format("%s: back leader generate key...\n")
                        % SUMOID << std::flush;
        if(generateSM4Key(sm4Key))
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
        std::string directory = "../../../examples/intersectionPlatoon/crypto/";
        std::string folder = SUMOID;
        std::string fullPath = directory + folder + "/cert.pem";
        std::string certificateStr = ReadCertificateToString(fullPath);

        value_k value;
        value.cert = certificateStr;
        sendKeyMsg(SUMOID, CERT_MSG, myPlnID, value);
    }

    /* leader receive certificate from followers, 1.verify it and 2.use pub key to encrypt sm4 key*/
    if(wsm->getUCommandType() == CERT_MSG && wsm->getReceiverID == SUMOID)
    {
        std::string certificateStr = wsm->getValue().cert;
        std::string sender = wsm->getSenderID();
        std::string caCertFilePath = "../../../examples/intersectionPlatoon/crypto/GKM/ca_cert.pem";

        bool isCertValid  = verifyCert(certificateStr, caCertFilePath);
        if(isCertValid)
        {
            std::string encryptKey = encryptSM4Key(certificateStr);
            value_k value;
            value.encryptSM4Key = encryptKey;
            sendKeyMsg(sender, ENCRYPT_KEY, myPlnID, value);
        }
    }

    /* follower receive encrypt key, decrypt and use it to communicate*/
    if(wsm->getUCommandType() == ENCRYPT_KEY && wsm->getReceiverID() == SUMOID) //multicast from leaderGKM
    {
        std::string ciphertext = wsm->getValue().encryptSM4Key;
        std::string privateKeyPath = "../../../examples/intersectionPlatoon/crypto/" + SUMOID + "/private_key.pem";
        decryptSM4Key(privateKeyPath, ciphertext);

        std::string sm4KeyString = byteArrayToHexString(sm4Key, SM4_KEY_LENGTH);
        LOG_INFO << boost::format("%s SM4 key: %s\n")% SUMOID % sm4KeyString << std::flush;
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


bool ApplVKeyManage::generateSM4Key(unsigned char* key)
{
    if(RAND_bytes(key, SM4_KEY_LENGTH) != 1)
    {
        throw omnetpp::cRuntimeError("SM4 key generation error");
        return false;
    }
    return true;
}


std::string ApplVKeyManage::ReadCertificateToString(const std::string &filepath)
{
    BIO *bio = BIO_new(BIO_s_file());
    if (BIO_read_filename(bio, filepath.c_str()) <= 0) {
        BIO_free(bio);
        throw omnetpp::cRuntimeError("Error in reading file");
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (cert == NULL) {
        BIO_free(bio);
        throw omnetpp::cRuntimeError("Error in reading x509");
    }

    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem, cert);

    char *dataStart = NULL;
    long dataLen = BIO_get_mem_data(mem, &dataStart);

    std::string result(dataStart, dataLen);

    X509_free(cert);
    BIO_free(bio);
    BIO_free(mem);

    return result;
}

bool ApplVKeyManage::verifyCert(const std::string &certString, const std::string &caCertFilePath)
{
    // Load CA certificate
    FILE *fp = fopen(caCertFilePath.c_str(), "r");
    if (!fp) {
        throw omnetpp::cRuntimeError("Failed to open CA certificate file");
    }
    X509 *caCert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!caCert) {
        throw omnetpp::cRuntimeError("Failed to read CA certificate from file");
    }

    // Extract public key from CA certificate
    EVP_PKEY *caPublicKey = X509_get_pubkey(caCert);
    if (!caPublicKey) {
        X509_free(caCert);
        throw omnetpp::cRuntimeError("Failed to extract public key from CA certificate");
    }

    // Load certificate from string
    BIO *bio = BIO_new_mem_buf(certString.data(), certString.size());
    if (!bio) {
        EVP_PKEY_free(caPublicKey);
        X509_free(caCert);
        throw omnetpp::cRuntimeError("Failed to create BIO");
    }

    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!cert) {
        BIO_free(bio);
        EVP_PKEY_free(caPublicKey);
        X509_free(caCert);
        throw omnetpp::cRuntimeError("Failed to read certificate from string");
    }

    // Verify certificate
    int result = X509_verify(cert, caPublicKey);

    X509_free(cert);
    BIO_free(bio);
    EVP_PKEY_free(caPublicKey);
    X509_free(caCert);

    return result == 1;
}


std::string ApplVKeyManage::encryptSM4Key(const std::string& publicKeyString)
{
    //
    CryptoPP::ByteQueue publicKeyBytes;
    publicKeyBytes.Put(reinterpret_cast<const CryptoPP::byte*>(publicKeyString.data()), publicKeyString.size());
    publicKeyBytes.MessageEnd();

    CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> publicKey;
    publicKey.Load(publicKeyBytes);

    //
    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encryptor(publicKey);

    //
    std::string plainText = byteArrayToHexString(sm4Key, SM4_KEY_LENGTH);
    std::string encryptedText;
    CryptoPP::StringSource(plainText, true,
        new CryptoPP::PK_EncryptorFilter(CryptoPP::GlobalRNG(), encryptor,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(encryptedText),
                false
            )
        )
    );

    return encryptedText;
}


void ApplVKeyManage::decryptSM4Key(std::string privateKeyFile, const std::string& cipherText)
{
    // 读取 PEM 格式的 SM2 私钥文件
    FILE* file = fopen(privateKeyFile.c_str(), "rb");
    if (!file) {
        throw std::runtime_error("Failed to open private key file");
    }
    EVP_PKEY* privateKey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    if (!privateKey) {
        throw std::runtime_error("Failed to read private key");
    }

    // 将 PEM 格式的 SM2 私钥转换为 Crypto++ 的私钥类型
    const EC_KEY* ecKey = EVP_PKEY_get0_EC_KEY(privateKey);
    CryptoPP::ECP::GroupParameters_EC<CryptoPP::ECP> params;
    const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
    CryptoPP::ECParameters ecParams;
    ecParams.InitializeFromGroupParameters(ecGroup);
    ecParams.GetCurve().Encode(params.GetCurve());
    params.SetSubgroupGenerator(CryptoPP::Integer(ecParams.GetSubgroupGenerator()));
    params.SetModulus(CryptoPP::Integer(ecParams.GetModulus()));
    params.SetCofactor(CryptoPP::Integer(ecParams.GetCofactor()));
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> groupParams(params);
    groupParams.SetPointCompression(true);
    CryptoPP::ECPrivateKey cryptoPrivateKey;
    cryptoPrivateKey.Initialize(groupParams);
    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> privateKeyImpl(cryptoPrivateKey);
    CryptoPP::Integer privateKeyInt(EC_KEY_get0_private_key(ecKey));
    privateKeyImpl.SetPrivateExponent(privateKeyInt);

    // 使用 Crypto++ 解密密文
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {0};
    std::string decryptedText;
    CryptoPP::StringSource(cipherText, true,
        new CryptoPP::PK_DecryptorFilter(prng, privateKeyImpl,
            new CryptoPP::StreamTransformationFilter(
                new CryptoPP::SM2Decryptor(), new CryptoPP::StringSink(decryptedText)
            )
        )
    );

    EVP_PKEY_free(privateKey);

    return decryptedText;
}


std::string ApplVKeyManage::byteArrayToHexString(const unsigned char* byteArray, int length)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < length; ++i)
    {
        ss << std::setw(2) << static_cast<unsigned>(byteArray[i]);
    }
    return ss.str();
}

}
