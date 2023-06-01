/****************************************************************************/
/// @file    yourCode.cc
/// @author
/// @author  second author name
/// @date    December 2017
///
/****************************************************************************/
// VENTOS, Vehicular Network Open Simulator; see http:?
// Copyright (C) 2013-2015
/****************************************************************************/
//
// This file is part of VENTOS.
// VENTOS is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "nodes/rsu/Intersection.h"

namespace VENTOS {

Define_Module(VENTOS::ApplRSUIntersection);

ApplRSUIntersection::~ApplRSUIntersection()
{

}


void ApplRSUIntersection::initialize(int stage)
{
    super::initialize(stage);

    if (stage == 0)
    {

    }
}


void ApplRSUIntersection::finish()
{
    super::finish();
}


void ApplRSUIntersection::executeEachTimeStep()
{
    // call the super method
    super::executeEachTimeStep();
}


void ApplRSUIntersection::handleSelfMsg(omnetpp::cMessage* msg)
{
    super::handleSelfMsg(msg);
}


void ApplRSUIntersection::onBeaconVehicle(BeaconVehicle* wsm)
{
    // pass it down!
    super::onBeaconVehicle(wsm);
}


void ApplRSUIntersection::onBeaconRSU(BeaconRSU* wsm)
{
    // pass it down!
    super::onBeaconRSU(wsm);
}


void ApplRSUIntersection::onDataMsg(dataMsg *wsm)
{
    // do not pass it down!
}


// receive PltInfo.msg from leader entering ZONE
void ApplRSUIntersection::onPltInfo(PltInfo* wsm)
{

}

// send PltCtrl.msg after calculating on PltInfo.msg from leader
void ApplRSUIntersection::sendPltCtrl(std::string receiverID, std::string receivingPlatoonID, double refSpeed, int optSize)
{

}

}
