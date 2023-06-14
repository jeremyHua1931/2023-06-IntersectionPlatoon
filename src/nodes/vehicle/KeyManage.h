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

namespace VENTOS {

class ApplVKeyManage : public ApplVPlatoonMg
{
private:
    typedef ApplVPlatoonMg super;
    typedef enum
        {
            KEY_REQ,
            KEY_CHANGE_REQ,
            REV_REQ,
            CERT_MSG,


            CERT_REQ,
            KEY_DELETE,
            DEL_ACK,
            ENCRYPT_KEY,
        } uCommand_k;
    bool grouKeyEnabled;
    unsigned char* sm4Key;  // assumed place at safe position in vehicle



public:
    ~ApplVKeyManage();
    virtual void initialize(int stage);
    virtual void finish();

protected:
    virtual void handleSelfMsg(omnetpp::cMessage*);
    void onBeaconVehicle(BeaconVehicle* wsm);
    void onBeaconRSU(BeaconRSU* wsm);
    void onKeyMsg(KeyMsg *wsm);

private:
    void sendKeyMsg(std::string receiverID, uCommand_k msgType, std::string receivingPlatoonID, value_k value = value_k());
    void generateSM4Key(unsigned char* key);
    std::string pem2string(std::string path);

};
}
#endif
