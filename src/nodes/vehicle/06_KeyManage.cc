/*
 * KeyMg.cc
 *
 *  Created on: Jun 13, 2023
 *      Author: puyijun
 */

#include "nodes/vehicle/06_KeyManage.h"
#include "baseAppl/ApplToPhyControlInfo.h"
#include "MIXIM_veins/nic/phy/PhyToMacControlInfo.h"
#include "MIXIM_veins/nic/phy/decider/DeciderResult80211.h"


namespace VENTOS {

Define_Module(VENTOS::ApplVKeyManage);

#define  SEND_DELAY_OFFSET  0.1
#define  SEND_TEST_OFFSET  3
#define  TEST_TEXT_LEN  16

ApplVKeyManage::~ApplVKeyManage()
{
    cancelAndDelete(TIMER);
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

        TIMER = new omnetpp::cMessage("timer to send test message");

        // if i am leader, play GKM
        // generate sm2 key, send
        if(myPlnDepth == 0 && grouKeyEnabled)
        {
            generateSM4Key();
            sendKeyMsg("multicast", CERT_REQ, myPlnID);
            std::string stringSM4Key = uint8ArrayToHexString(sm4key, SM4_KEY_SIZE);
            LOG_INFO << boost::format("leader--%s SM4 key: %s\n")% SUMOID %stringSM4Key << std::flush;
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
    if(msg == TIMER && grouKeyEnabled)
    {
        cancelEvent(TIMER);
        uint8_t plainText[TEST_TEXT_LEN]= {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
                0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};
        SM4_KEY formedSM4Key;
        sm4_set_encrypt_key(&formedSM4Key, sm4key);
        uint8_t cbuf[TEST_TEXT_LEN];
        sm4_encrypt(&formedSM4Key, plainText, cbuf);

        BufferData bufCipherText;
        bufCipherText.content = cbuf;
        bufCipherText.len = TEST_TEXT_LEN;
        value_k value;
        std::vector<uint8_t> CipherTextEncode = encodeBufferData(bufCipherText);
        value.testMsg = CipherTextEncode;
        std::string stringPlainText = uint8ArrayToHexString(plainText, TEST_TEXT_LEN);
        LOG_INFO << boost::format("\n%s sent secret message: %s\n\n") % SUMOID % stringPlainText << std::flush;
        sendKeyMsg("broadcast", TEST_MSG, "broadcast", value);
    }
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

    if(signalID == memberChangeSignal && senderSUMOID == SUMOID && grouKeyEnabled)
    {
        LOG_WARNING << boost::format("%s: front leader change key...\n")
                % SUMOID << std::flush;
        generateSM4Key();
        sendKeyMsg("multicast", CERT_REQ, myPlnID);
    }
    else if(signalID == newLeaderSignal && senderSUMOID == SUMOID && grouKeyEnabled)
    {
        LOG_WARNING << boost::format("%s: back leader generate key...\n")
                        % SUMOID << std::flush;
        generateSM4Key();
        sendKeyMsg("multicast", CERT_REQ, myPlnID);
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
    if(wsm->getUCommandType() == CERT_REQ && wsm->getSenderID() == myPlnID && grouKeyEnabled)
    {
        std::string myCertFilePath = "/home/jeremy/IntersectionPlatoon/examples/intersectionPlatoon/cert&key/" + SUMOID + "/certificate.pem";
        BufferData myCert = readCertificateFromPath(myCertFilePath);
        // check
        std::string myCertStringP = uint8ArrayToHexString(myCert.content, myCert.len);

        value_k value;
        std::vector<uint8_t> myCertEncode = encodeBufferData(myCert);
        value.certificate = myCertEncode;
        sendKeyMsg(myPlnID, CERT_MSG, myPlnID, value);
    }

    /* leader receive certificate from followers, 1.verify it and 2.use pub key to encrypt sm4 key*/
    if(wsm->getUCommandType() == CERT_MSG && wsm->getReceiverID() == SUMOID && grouKeyEnabled)
    {
        std::vector<uint8_t> certEncode= wsm->getValue().certificate;
        BufferData cert = decodeBufferData(certEncode);
        std::string sender = wsm->getSenderID();
        std::string caCertFilePath = "/home/jeremy/IntersectionPlatoon/examples/intersectionPlatoon/cert&key/CA/rootcacert.pem";
        BufferData caCert = readCertificateFromPath(caCertFilePath);
        // check
        std::string certStringP = uint8ArrayToHexString(cert.content, cert.len);
        // verify
        const char* signerId = "ca";
        bool isCertValid  = verifyCert(cert, caCert, signerId);
        if(isCertValid)
        {
            // encrypt and send
//            LOG_INFO << boost::format("%s verify %s success\n") % SUMOID % sender << std::flush;
            BufferData encryptKey = encryptSM4Key(cert);
            std::vector<uint8_t> keyEncode = encodeBufferData(encryptKey);
            value_k value;
            value.encryptedKey = keyEncode;
            sendKeyMsg(sender, ENCRYPT_KEY, myPlnID, value);
        }
        if (!TIMER->isScheduled())
        {
            scheduleAt(omnetpp::simTime() + SEND_TEST_OFFSET, TIMER);
        }
    }

    /* follower receive encrypt key, decrypt and use it to communicate*/
    if(wsm->getUCommandType() == ENCRYPT_KEY && wsm->getReceiverID() == SUMOID && grouKeyEnabled) //multicast from leaderGKM
    {
        LOG_INFO << boost::format("%s received sm4 key\n")% SUMOID << std::flush;

        std::vector<uint8_t> keyEncode = wsm->getValue().encryptedKey;
        BufferData ciphertext = decodeBufferData(keyEncode);
        std::string privateKeyPath = "/home/jeremy/IntersectionPlatoon/examples/intersectionPlatoon/cert&key/" + SUMOID + "/private_key.pem";
        const char* pass = "1";
        BufferData decryptKey = decryptSM4Key(privateKeyPath, pass, ciphertext);
        std::string stringSM4Key = uint8ArrayToHexString(sm4key,decryptKey.len);
        LOG_INFO << boost::format("%s SM4 key: %s\n")% SUMOID %stringSM4Key << std::flush;
    }

    if(wsm->getUCommandType() == TEST_MSG && std::string(wsm->getReceiverID()) == "broadcast" && std::string(wsm->getReceivingPlatoonID()) == "broadcast" && grouKeyEnabled)
    {
        std::vector<uint8_t> CipherTextEncode = wsm->getValue().testMsg;
        BufferData bufCipherText = decodeBufferData(CipherTextEncode);
        uint8_t cbuf[TEST_TEXT_LEN];
        std::copy(bufCipherText.content, bufCipherText.content + TEST_TEXT_LEN, cbuf);
        uint8_t pbuf[TEST_TEXT_LEN];
        SM4_KEY formedSM4Key;
        sm4_set_decrypt_key(&formedSM4Key, sm4key);
        sm4_decrypt(&formedSM4Key, cbuf, pbuf);
        BufferData bufPlainText;
        bufPlainText.content = pbuf;
        bufPlainText.len = TEST_TEXT_LEN;
        std::string plainText = uint8ArrayToHexString(bufPlainText.content, bufPlainText.len);
        LOG_INFO << boost::format("%s received secret message: %s\n\n") % SUMOID % plainText << std::flush;
    }

    if(wsm->getUCommandType() == KEY_DELETE && wsm->getSenderID() == myPlnID && grouKeyEnabled) //multicast from leaderleaderGKM
    {
        // followers, delete key
        // ...
    }

    if(wsm->getUCommandType() == DEL_ACK && wsm->getReceiverID() == SUMOID && grouKeyEnabled) //unicast for from followers
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


void ApplVKeyManage::generateSM4Key()
{
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
            sm4key[i] = rand() % 256;
        }
}

ApplVKeyManage::BufferData ApplVKeyManage::readCertificateFromPath(const std::string &certificatePath)
{
    uint8_t certData[CERT_BUF];
    size_t certLen = sizeof(certData);
    FILE *certFile = fopen(certificatePath.c_str(), "r");

    if (!certFile) {
        throw std::runtime_error("open certificate file error");
    }

    if (x509_cert_from_pem(certData, &certLen, sizeof(certData), certFile) != 1) {
        throw std::runtime_error("read certificate error");
    }
    fclose(certFile);
    BufferData cert;
    cert.content = certData;
    cert.len = certLen;
    return cert;
}

bool ApplVKeyManage::verifyCert(const BufferData& cert, const BufferData& cacert, const char* signerId)
{
    size_t signerIdLen = strlen(signerId);
    return (x509_cert_verify_by_ca_cert(cert.content, cert.len, cacert.content, cacert.len, signerId, signerIdLen) == 1);
}

ApplVKeyManage::BufferData ApplVKeyManage::encryptSM4Key(const BufferData& cert)
{
    SM2_KEY publicKey;

    if (x509_cert_get_subject_public_key(cert.content, cert.len, &publicKey) != 1) {
        throw std::runtime_error("Failed to extract subject public key from X.509 certificate");
    }

    // encrypt data
    uint8_t ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
    size_t ciphertextLen;

    if (sm2_encrypt(&publicKey, sm4key, SM4_KEY_SIZE, ciphertext, &ciphertextLen) != 1) {
        throw std::runtime_error("encrypt error");
    }
    BufferData ciphertexts;
    ciphertexts.content = ciphertext;
    ciphertexts.len = ciphertextLen;
    return ciphertexts;
}

ApplVKeyManage::BufferData ApplVKeyManage::decryptSM4Key(const std::string privateKeyFile, const char *pass, const BufferData& ciphertext)
{
    SM2_KEY privateKey;
    FILE *fp = fopen(privateKeyFile.c_str(), "r");

    if (fp == NULL) {
        throw std::runtime_error("Failed to open private key file");
    }
    if (sm2_private_key_info_decrypt_from_pem(&privateKey, pass, fp) != 1) {
        throw std::runtime_error("Failed to read SM2 private key from PEM file");
    }

    fclose(fp);
    // decrypt
    uint8_t plaintext[SM2_MAX_PLAINTEXT_SIZE];
    size_t plaintextLen;
    if (sm2_decrypt(&privateKey, ciphertext.content, ciphertext.len, plaintext, &plaintextLen) != 1) {
        throw std::runtime_error("decrypt error");
    }
    BufferData plaintexts;
    plaintexts.content = plaintext;
    plaintexts.len = plaintextLen;
    for (int i = 0; i < SM4_KEY_SIZE; i++) {
            sm4key[i] = plaintext[i];
        }
    return plaintexts;
}

std::string ApplVKeyManage::uint8ArrayToHexString(const uint8_t* array, size_t size) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; i++) {
        oss << std::setw(2) << static_cast<int>(array[i]);
    }
    return oss.str();
}

std::vector<uint8_t> ApplVKeyManage::encodeBufferData(const BufferData& bufferData)
{
    std::vector<uint8_t> encodedData;

    for (size_t i = 0; i < bufferData.len; ++i)
    {
        encodedData.push_back(bufferData.content[i]);
    }

    return encodedData;
}

ApplVKeyManage::BufferData ApplVKeyManage::decodeBufferData(const std::vector<uint8_t>& encodedData)
{
    BufferData bufferData;
    bufferData.len = encodedData.size();

    bufferData.content = new uint8_t[bufferData.len];

    for (size_t i = 0; i < bufferData.len; ++i)
    {
        bufferData.content[i] = encodedData[i];
    }

    return bufferData;
}


}
