//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//
cplusplus {{
    #include "WaveShortMessage_m.h"
    #include "mobility/TraCICoord.h"
}}

class Veins::WaveShortMessage;
class noncobject TraCICoord;

namespace VENTOS;

packet PltInfo extends WaveShortMessage
{
	string  senderID;
	string  receiverID; // myFullId instead of SUMOID
	string  sendingPlatoonID;
    double TG = -1;  	// hw_preset
    TraCICoord pos;     // current position
    double speed;       // current speed
    double maxAccel;    // max acceleration
    double maxDecel;    // max decceleration
};