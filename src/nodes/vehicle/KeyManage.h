/*
 * KeyManage.h
 *
 *  Created on: Jun 13, 2023
 *      Author: puyijun
 */

#ifndef ApplVKEYMANAGE_H
#define ApplVKEYMANAGE_H

#include "nodes/vehicle/05_PlatoonMg.h"
#include "msg/dataMsg_m.h"
#include "msg/KeyMsg_m.h"
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>


#define SM4_KEY_LENGTH 16

namespace VENTOS {

class ApplVKeyManage : public ApplVPlatoonMg
{
private:
    typedef ApplVPlatoonMg super;
    typedef enum
        {
            CERT_REQ,        // leader ask followers for cert(sm2 pub key)
            CERT_MSG,        // follower send cert to leader
            ENCRYPT_KEY,     // leader send encrypt sm4 key(by sm2 pub key)

            KEY_DELETE,      // leader ask followers to delete key
            DEL_ACK,         // follower send ack after delete

        } uCommand_k;
    bool grouKeyEnabled;
    std::vector<unsigned char> sm4Key;   // assumed place at safe position in vehicle



public:
    ~ApplVKeyManage();
    virtual void initialize(int stage);
    virtual void finish();
    void receiveSignal(omnetpp::cComponent *source, omnetpp::simsignal_t signalID, omnetpp::cObject *obj, omnetpp::cObject *details);

protected:
    virtual void handleSelfMsg(omnetpp::cMessage*);
    void onBeaconVehicle(BeaconVehicle* wsm);
    void onBeaconRSU(BeaconRSU* wsm);
    void onKeyMsg(KeyMsg *wsm);

private:
    void sendKeyMsg(std::string receiverID, uCommand_k msgType, std::string receivingPlatoonID, value_k value = value_k());
    bool generateSM4Key();
    std::string encodeSM4Key();
    void decodeSM4Key(const std::string& encodedKey);
    std::string ReadCertificateToString(const std::string &filepath);
    bool verifyCert(const std::string &certString, const std::string &caCertFilePath);
    std::string encryptSM4Key(const std::string &certString);
    std::string decryptSM4Key(std::string privateKeyPath, const std::string& ciphertext);
    std::string sm4KeyToString();
    void stringToSm4Key(const std::string& keyString);
    std::string encryptWithSM2PublicKey(const std::string& sm2CertificateString, const std::string& plaintext);
    std::string decryptWithSM2PrivateKey(const std::string& privateKeyPath, const std::string& ciphertext);
};
}
#endif
