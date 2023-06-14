/*
 * GKM.cc
 *
 *  Created on: Jun 13, 2023
 *      Author: puyijun
 */
#include "nodes/rsu/GKM.h"

namespace VENTOS {

Define_Module(VENTOS::ApplRSUGKM);

ApplRSUGKM::~ApplRSUGKM()
{

}


void ApplRSUGKM::initialize(int stage)
{
    super::initialize(stage);

    if (stage == 0)
    {

    }
}


void ApplRSUGKM::finish()
{
    super::finish();
}

void ApplRSUGKM::executeEachTimeStep()
{
    // call the super method
    super::executeEachTimeStep();
}


void ApplRSUGKM::handleSelfMsg(omnetpp::cMessage* msg)
{
    super::handleSelfMsg(msg);
}


void ApplRSUGKM::onBeaconVehicle(BeaconVehicle* wsm)
{
    // pass it down!
    super::onBeaconVehicle(wsm);
}


void ApplRSUGKM::onBeaconRSU(BeaconRSU* wsm)
{
    // pass it down!
    super::onBeaconRSU(wsm);
}

void ApplRSUGKM::onKeyManage()
{

}

void ApplRSUGKM::sendEncryptKey()
{

}

}


