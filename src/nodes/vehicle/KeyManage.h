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
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/asn.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/oids.h>
//#include <cryptopp/pem.h>
#include <cryptopp/files.h>

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
    unsigned char sm4Key[SM4_KEY_LENGTH];   // assumed place at safe position in vehicle



public:
    ~ApplVKeyManage();
    virtual void initialize(int stage);
    virtual void finish();
    void receiveSignal(omnetpp::cComponent *source, omnetpp::simsignal_t signalID, omnetpp::cObject *obj, omnetpp::cObject *details);

protected:
    virtual void handleSelfMsg(omnetpp::cMessage*);
    void onBeaconVehicle(BeaconVehicle* wsm);
    void onBeaconRSU(BeaconRSU* wsm);

private:
    void onKeyMsg(KeyMsg *wsm);
    void sendKeyMsg(std::string receiverID, uCommand_k msgType, std::string receivingPlatoonID, value_k value = value_k());
    bool generateSM4Key(unsigned char* key);
    std::string ReadCertificateToString(const std::string &filepath);
    bool verifyCert(const std::string &certString, const std::string &caCertFilePath);
    std::string encryptSM4Key(const std::string &certString);
    void decryptSM4Key(std::string privateKeyPath, const std::string& ciphertext);
    std::string byteArrayToHexString(const unsigned char* byteArray, int length);
};
}
#endif
