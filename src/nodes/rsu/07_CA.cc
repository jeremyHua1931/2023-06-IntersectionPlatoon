/*
 * GKM.cc
 *
 *  Created on: Jun 13, 2023
 *      Author: puyijun
 */
#include "07_CA.h"

namespace VENTOS {

Define_Module(VENTOS::ApplRSUCA);

ApplRSUCA::~ApplRSUCA()
{

}


void ApplRSUCA::initialize(int stage)
{
    super::initialize(stage);

    if (stage == 0)
    {

    }
}


void ApplRSUCA::finish()
{
    super::finish();
}

void ApplRSUCA::executeEachTimeStep()
{
    // call the super method
    super::executeEachTimeStep();
}


void ApplRSUCA::handleSelfMsg(omnetpp::cMessage* msg)
{
    super::handleSelfMsg(msg);
}


void ApplRSUCA::onBeaconVehicle(BeaconVehicle* wsm)
{
    // pass it down!
    super::onBeaconVehicle(wsm);
}


void ApplRSUCA::onBeaconRSU(BeaconRSU* wsm)
{
    // pass it down!
    super::onBeaconRSU(wsm);
}

void ApplRSUCA::onKeyMsg()
{

}


}


