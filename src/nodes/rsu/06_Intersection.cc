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

#include "06_Intersection.h"

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
        Vmax = par("Vmax").doubleValue();
        Vmin = par("Vmin").doubleValue();
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
    LOG_INFO << boost::format("%s receive PltInfo: senderID: %s, receiverID: %s, TG: %.2f, pos_x: %.2f, pos_y: %.2f, speed: %.2f \n")
                                    %SUMOID.c_str()
                                    %wsm->getSenderID()
                                    %wsm->getReceiverID()
                                    %wsm->getTG()
                                    %wsm->getPos().x
                                    %wsm->getPos().y
                                    %wsm->getSpeed()
                                << std::flush;
    if((strcmp(wsm->getReceiverID(), myFullId) == 0))
    {
        // collect value from wsm
        std::string sender = wsm->getSenderID();
        std::string sendingPlatoonID = wsm->getSendingPlatoonID();
        double TG = wsm->getTG();
        TraCICoord pos = wsm->getPos();
        double speed = wsm->getSpeed();
        double maxAccel = wsm->getMaxAccel();
        double maxDecel = wsm->getMaxDecel();

        // get control value
        CtrlValue cValue = getCtrlValue(TG, pos, speed, maxAccel, maxDecel);

        // send PltCtrl.msg
        sendPltCtrl(sender, sendingPlatoonID, cValue.refVelocity, cValue.optSize);
    }
}

ApplRSUIntersection::CtrlValue ApplRSUIntersection::getCtrlValue(double TG, TraCICoord pos, double speed, double maxAccel, double maxDecel)
{
    double distance = abs(pos.x - (-14.0)); //-14 is from sumo->net.xml file, position of waiting line
    double threshold;

    // var from TrafficLight
    enum Stage {
                GO_STAGE,
                WAIT_STAGE
            };
    Stage currentStage;
    int nextSwitchTimeMs = TraCI->TLGetNextSwitchTime("2");
    double nextSwitchTime = nextSwitchTimeMs / 1000;
    double currentTime = omnetpp::simTime().dbl();
    double remainingTime = nextSwitchTime - currentTime;
    double greenDuration = 30.0,
           redDuration = 30.0,
           yellowDuration = 6.0; // from from sumo->net.xml file
    double nextRedTime = 0., //for go_stage optSize
           nextGreenTime = 0., //for wait_stage v_ref
           leaderArrivalTime; //for go_stage optSize
    double adjAccel = maxAccel / 4; //do not use maxAccel for optSize, in case LAT less than real
    std::string state = TraCI->TLGetState("2");
    char nowSignal = state[17];
    // return value
    double refVelocity;
    int optSize;

    if(remainingTime < 0)
    {
        throw omnetpp::cRuntimeError("TrafficLight next switch time wrong!");
    }

    // determine stage
    if(nowSignal == 'G') // now green
    {
        threshold = distance / speed;
        if(remainingTime > threshold)
        {
            currentStage = GO_STAGE;
            nextRedTime = remainingTime;
        }
        else
        {
            currentStage = WAIT_STAGE;
            nextGreenTime = remainingTime + redDuration;
        }
    }
    else if(nowSignal == 'r')   // now red
    {
        threshold = distance / ApplRSUIntersection::Vmax;
        if(remainingTime > threshold)
        {
            currentStage = WAIT_STAGE;
            nextGreenTime = remainingTime;
        }
        else
        {
            currentStage = GO_STAGE;
            nextRedTime = remainingTime + greenDuration;
        }
    }
    else // now yellow
    {
        currentStage = WAIT_STAGE;
        nextGreenTime = remainingTime + greenDuration; // remainingTime means t_green
    }

    // calculate ref_speed/opt_size for different stage
    switch(currentStage)
    {
        case GO_STAGE:
            if(((ApplRSUIntersection::Vmax * ApplRSUIntersection::Vmax - speed * speed) / 2 * adjAccel) >= distance)
            {
                leaderArrivalTime = (std::sqrt(2 * adjAccel * distance + speed * speed) - speed) / adjAccel;
                std::cout << "xiao " <<leaderArrivalTime << std::endl;
            }
            else
            {
                double t1 = (ApplRSUIntersection::Vmax - speed) / adjAccel,
                       d2 = distance - ((ApplRSUIntersection::Vmax * ApplRSUIntersection::Vmax - speed * speed) / (2 * adjAccel)),
                       t2 = d2 / ApplRSUIntersection::Vmax;
                leaderArrivalTime = t1 + t2;
//                std::cout <<leaderArrivalTime << " " << t1 << " " << d2 << " " << t2 << " " << ApplRSUIntersection::Vmax << std::endl;
            }

            refVelocity = ApplRSUIntersection::Vmax;
            optSize = floor((nextRedTime - leaderArrivalTime) / TG) + 1;
            break;
        case WAIT_STAGE:
            refVelocity = distance / nextGreenTime - 1;
            optSize = floor(greenDuration / TG) + 1;
            break;
    }

    LOG_INFO << boost::format(" distance: %.2f\n nowSignal: %s\n remainingTime: %.2f\n threshold: %.2f\n currentStage: %d\n "
            "nextGreenTime: %.2f\n nextRedTime: %.2f\n leaderArrivalTime: %.2f\n refVelocity: %.2f\n optSize:%.2f\n")
                                %distance
                                %nowSignal
                                %remainingTime
                                %threshold
                                %currentStage
                                %nextGreenTime
                                %nextRedTime
                                %leaderArrivalTime
                                %refVelocity
                                %optSize
                                << std::flush;

    ApplRSUIntersection::CtrlValue cValue;
    cValue.refVelocity = refVelocity;
    cValue.optSize = optSize;
    return cValue;
}

// send PltCtrl.msg
void ApplRSUIntersection::sendPltCtrl(std::string receiverID, std::string receivingPlatoonID, double refSpeed, int optSize)
{
    PltCtrl* wsm = new PltCtrl("pltCtrl", TYPE_PLATOON_CONTROL);

    wsm->setWsmVersion(1);
    wsm->setSecurityType(1);
    wsm->setChannelNumber(Veins::Channels::CCH);
    wsm->setDataRate(1);
    wsm->setPriority(dataPriority);
    wsm->setPsid(0);

    wsm->setSenderID(SUMOID.c_str());
    wsm->setReceiverID(receiverID.c_str());
    wsm->setReceivingPlatoonID(receivingPlatoonID.c_str());
    wsm->setRefSpeed(refSpeed);
    wsm->setOptSize(optSize);

    // add header length
    wsm->addBitLength(headerLength);

    // add payload length
    wsm->addBitLength(dataLengthBits);

    send(wsm, lowerLayerOut);
}

}
