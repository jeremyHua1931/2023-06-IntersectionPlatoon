/*
 * GKM.h
 *
 *  Created on: Jun 13, 2023
 *      Author: puyijun
 */

#ifndef APPLRSUGKM_H
#define APPLRSUGKM_H

#include "06_Intersection.h"
#include "msg/KeyMsg_m.h"


namespace VENTOS {

class ApplRSUCA : public ApplRSUIntersection
{
private:
    typedef ApplRSUIntersection super;

private:

public:
    ~ApplRSUCA();
    virtual void initialize(int stage);
    virtual void finish();

protected:
    virtual void handleSelfMsg(omnetpp::cMessage*);
    void onBeaconVehicle(BeaconVehicle* wsm);
    void onBeaconRSU(BeaconRSU* wsm);
    void executeEachTimeStep();
    void onKeyMsg();
};

}

#endif
