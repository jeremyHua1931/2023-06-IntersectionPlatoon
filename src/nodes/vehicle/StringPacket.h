/*
 * KeyManage.h
 *
 *  Created on: Jun 13, 2023
 *      Author: puyijun
 */

#ifndef __STRINGPACKET_H__
#define __STRINGPACKET_H__

#include <omnetpp.h>

class StringPacket : public omnetpp::cPacket
{
private:
    std::string str;
public:
    StringPacket(const char *name = nullptr, int kind = 0) : omnetpp::cPacket(name, kind) {}
    void setString(const std::string &s) { str = s; }
    const std::string& getString() const { return str; }
};

#endif // __STRINGPACKET_H__
