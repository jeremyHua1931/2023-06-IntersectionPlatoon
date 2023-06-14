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
#include <openssl/evp.h>
#include <openssl/rand.h>

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

        OpenSSL_add_all_algorithms();

        // if i am leader, play GKM
        if(myPlnDepth == 0)
        {
            generateSM4Key(sm4Key);
            value_k value;
            sendKeyMsg("multicast", ENCRYPT_KEY, myPlnID, value);
        }
    }
}


void ApplVKeyManage::finish()
{
    super::finish();
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


void ApplVKeyManage::onBeaconRSU(BeaconRSU* wsm)
{
    // pass it down!
    super::onBeaconRSU(wsm);
}


void ApplVKeyManage::onKeyMsg(KeyMsg *wsm)
{
    if(wsm->getUCommandType() == CERT_REQ && wsm->getSenderID() == myPlnID)
    {
        // followers, send CERT_MSG to GKM
    }

    if(wsm->getUCommandType() == ENCRYPT_KEY && wsm->getReceivingPlatoonID() == myPlnID) //multicast from leaderGKM
    {
        // TTTEST
        /*   encrypt   */
        generateSM4Key(sm4Key);

        // The message to be encrypted
        const char* plaintext = "this is a message";

        // Create and initialize the context for encryption
        EVP_CIPHER_CTX* ctx_enc = EVP_CIPHER_CTX_new();
        if(!ctx_enc) {
            std::cerr << "Failed to create the context for encryption" << std::endl;
            return ;
        }

        // Initialize the encryption operation
        if(EVP_EncryptInit_ex(ctx_enc, EVP_sm4_ecb(), NULL, sm4Key, NULL) != 1) {
            std::cerr << "Failed to initialize the encryption operation" << std::endl;
            return ;
        }

        // Provide the plaintext to be encrypted
        int plaintext_len = strlen(plaintext);
        int ciphertext_len;
        unsigned char ciphertext[64];  // make sure it is large enough
        if(EVP_EncryptUpdate(ctx_enc, ciphertext, &ciphertext_len, (unsigned char*)plaintext, plaintext_len) != 1) {
            std::cerr << "Failed to encrypt the plaintext" << std::endl;
            return ;
        }

        // Finalize the encryption
        int len;
        if(EVP_EncryptFinal_ex(ctx_enc, ciphertext + ciphertext_len, &len) != 1) {
            std::cerr << "Failed to finalize the encryption" << std::endl;
            return ;
        }
        ciphertext_len += len;

        // Clean up encryption context
        EVP_CIPHER_CTX_free(ctx_enc);

        // Create and initialize the context for decryption
        EVP_CIPHER_CTX* ctx_dec = EVP_CIPHER_CTX_new();
        if(!ctx_dec) {
            std::cerr << "Failed to create the context for decryption" << std::endl;
            return ;
        }

        // Initialize the decryption operation
        if(EVP_DecryptInit_ex(ctx_dec, EVP_sm4_ecb(), NULL, sm4Key, NULL) != 1) {
            std::cerr << "Failed to initialize the decryption operation" << std::endl;
            return ;
        }

        // Provide the ciphertext to be decrypted
        unsigned char decrypted[64];  // make sure it is large enough
        int decrypted_len;
        if(EVP_DecryptUpdate(ctx_dec, decrypted, &decrypted_len, ciphertext, ciphertext_len) != 1) {
            std::cerr << "Failed to decrypt the ciphertext" << std::endl;
            return;
        }

        // Finalize the decryption
        if(EVP_DecryptFinal_ex(ctx_dec, decrypted + decrypted_len, &len) != 1) {
            std::cerr << "Failed to finalize the decryption" << std::endl;
            return ;
        }
        decrypted_len += len;

        // Clean up decryption context
        EVP_CIPHER_CTX_free(ctx_dec);

        // Null-terminate the decrypted text
        decrypted[decrypted_len] = '\0';

        // Print the decrypted text
        std::cout << "Decrypted text: " << decrypted << std::endl;

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


std::string ApplVKeyManage::pem2string(std::string path)
{
    std::ifstream pemFile(path);
    if (!pemFile) {
        throw std::runtime_error("Could not open pem file at " + path);
    }
    std::string pemStr((std::istreambuf_iterator<char>(pemFile)),
                        std::istreambuf_iterator<char>());
    return pemStr;
}

void ApplVKeyManage::generateSM4Key(unsigned char* key)
{
    if (RAND_bytes(key, 16) != 1) {
        std::cerr << "Error generating random SM4 key" << std::endl;
        exit(EXIT_FAILURE);
    }
}

}
