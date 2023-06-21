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
#include <gmssl/x509.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/sm4.h>

//#define SM4_KEY_SIZE 16
#define CERT_BUF 4096

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

            TEST_MSG,

        } uCommand_k;
    bool grouKeyEnabled;
    omnetpp::cMessage* TIMER = NULL;
    uint8_t sm4key[SM4_KEY_SIZE];   // assumed place at safe position in vehicle
    struct BufferData
    {
        uint8_t* content;
        size_t len;
    };

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
    void generateSM4Key();
    void decodeSM4Key(const std::string& encodedKey);
    BufferData readCertificateFromPath(const std::string &certificatePath);
    bool verifyCert(const BufferData& cert, const BufferData& cacert, const char* signerId);
    BufferData encryptSM4Key(const BufferData& cert);
    BufferData decryptSM4Key(const std::string privateKeyFile, const char *pass, const BufferData& ciphertext);
    std::string uint8ArrayToHexString(const uint8_t* array, size_t size);
    std::vector<uint8_t> encodeBufferData(const BufferData& bufferData);
    BufferData decodeBufferData(const std::vector<uint8_t>& encodedData);
};
}
#endif
