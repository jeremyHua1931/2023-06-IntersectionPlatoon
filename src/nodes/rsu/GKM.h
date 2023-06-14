/*
 * GKM.h
 *
 *  Created on: Jun 13, 2023
 *      Author: puyijun
 */

#ifndef APPLRSUGKM_H
#define APPLRSUGKM_H

#include "nodes/rsu/Intersection.h"
//#include "nodes/vehicle/KeyManage.h"
#include "msg/KeyMsg_m.h"


namespace VENTOS {

class ApplRSUGKM : public ApplRSUIntersection
{
private:
    typedef ApplRSUIntersection super;

private:
    void sendEncryptKey();

public:
    ~ApplRSUGKM();
    virtual void initialize(int stage);
    virtual void finish();

protected:
    virtual void handleSelfMsg(omnetpp::cMessage*);
    void onBeaconVehicle(BeaconVehicle* wsm);
    void onBeaconRSU(BeaconRSU* wsm);
    void executeEachTimeStep();
    void onKeyManage();
};

}

#endif
