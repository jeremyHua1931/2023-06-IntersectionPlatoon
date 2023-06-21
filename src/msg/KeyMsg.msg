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
#include <deque>
typedef std::vector<uint8_t> uintVector;

typedef struct 
{   
    // values used by CERT_MSG
	uintVector certificate;
    // values used by ENCRYPT_KEY
    uintVector encryptedKey;
    
    uintVector testMsg;
} value_k;

}}

class Veins::WaveShortMessage;
class noncobject value_k;

namespace VENTOS;

packet KeyMsg extends WaveShortMessage 
{
    string  senderID;
	string  receiverID;
    int     uCommandType;
    string  sendingPlatoonID;
    string  receivingPlatoonID;
    value_k value; // some uCommands need this field to 
                   // send extra infromation to the receiver
};