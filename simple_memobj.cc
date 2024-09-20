/*
 * Copyright (c) 2017 Jason Lowe-Power
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "learning_gem5/part2/simple_memobj.hh"

#include "base/trace.hh"
#include "debug/SimpleMemobj.hh"


#include <bitset>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <math.h>
#include <algorithm>
#include <map>

std::map<uint64_t, std::string> dmap;

class HammingCode {
private:
    std::string data;
    std::vector<int> hamming_code;

public:
    HammingCode(std::string data) : data(data), hamming_code() {}

    void generate_code() {
        int r = 0;
        while (pow(2, r) < data.length() + r + 1) {
            r++;
        }
        hamming_code.resize(data.length() + r, 0);

        std::vector<int> parity_positions;
        for (int i = 0; i < r; i++) {
            parity_positions.push_back(pow(2, i));
        }

        int j = 0;
        for (size_t i = 0; i < hamming_code.size(); i++) {
            if (std::find(parity_positions.begin(), parity_positions.end(), i + 1) == parity_positions.end()) {
                hamming_code[i] = data[j] - '0';
                j++;
            }
        }

        for (int i = 0; i < r; i++) {
            int parity_index = parity_positions[i] - 1;
            int parity = 0;
            for (size_t j = 0; j < hamming_code.size(); j++) {
                if (((j + 1) >> i) & 1) {
                    parity ^= hamming_code[j];
                }
            }
            hamming_code[parity_index] = parity;
        }
    }

    std::string get_code() {
        std::string code = "";
        for (int bit : hamming_code) {
            code += std::to_string(bit);
        }
        return code;
    }

    void corrupt_code() {
        int index = rand() % hamming_code.size();
        hamming_code[index] = 1 - hamming_code[index];
    }

    std::string correct_ham(std::string hamcode) {
        int pos = 0;
        std::vector<int> list1(hamcode.length());
        for (size_t i = 0; i < hamcode.length(); i++) {
            list1[i] = hamcode[i] - '0';
            if (hamcode[i] == '1') {
                pos ^= i + 1;
            }
        }
        if (pos != 0) {
            list1[pos - 1] = (list1[pos - 1] == 0) ? 1 : 0;
        }
        std::string corrected_code = "";
        for (int bit : list1) {
            corrected_code += std::to_string(bit);
        }
        return corrected_code;
    }

    std::string get_decode(std::string hamcode) {
        std::string decodeham = "";
        for (size_t i = 0; i < hamcode.length(); i++) {
            if (__builtin_popcount(i + 1) == 1 || i == 0) {
                continue;
            } else {
                decodeham += hamcode[i];
            }
        }
        return decodeham;
    }
};

namespace gem5
{

SimpleMemobj::SimpleMemobj(const SimpleMemobjParams &params) :
    SimObject(params),
    instPort(params.name + ".inst_port", this),
    dataPort(params.name + ".data_port", this),
    memPort(params.name + ".mem_side", this),
    blocked(false)
{
}

Port &
SimpleMemobj::getPort(const std::string &if_name, PortID idx)
{
    panic_if(idx != InvalidPortID, "This object doesn't support vector ports");

    // This is the name from the Python SimObject declaration (SimpleMemobj.py)
    if (if_name == "mem_side") {
        return memPort;
    } else if (if_name == "inst_port") {
        return instPort;
    } else if (if_name == "data_port") {
        return dataPort;
    } else {
        // pass it along to our super class
        return SimObject::getPort(if_name, idx);
    }
}

void
SimpleMemobj::CPUSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the memobj is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    if (!sendTimingResp(pkt)) {
        blockedPacket = pkt;
    }
}

AddrRangeList
SimpleMemobj::CPUSidePort::getAddrRanges() const
{
    return owner->getAddrRanges();
}

void
SimpleMemobj::CPUSidePort::trySendRetry()
{
    if (needRetry && blockedPacket == nullptr) {
        // Only send a retry if the port is now completely free
        needRetry = false;
        DPRINTF(SimpleMemobj, "Sending retry req for %d\n", id);
        sendRetryReq();
    }
}

void
SimpleMemobj::CPUSidePort::recvFunctional(PacketPtr pkt)
{
    // Just forward to the memobj.
    return owner->handleFunctional(pkt);
}

bool
SimpleMemobj::CPUSidePort::recvTimingReq(PacketPtr pkt)
{
    // Just forward to the memobj.
    if (!owner->handleRequest(pkt)) {
        needRetry = true;
        return false;
    } else {
        return true;
    }
}

void
SimpleMemobj::CPUSidePort::recvRespRetry()
{
    // We should have a blocked packet if this function is called.
    assert(blockedPacket != nullptr);

    // Grab the blocked packet.
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;

    // Try to resend it. It's possible that it fails again.
    sendPacket(pkt);
}

void
SimpleMemobj::MemSidePort::sendPacket(PacketPtr pkt)
{
    // Note: This flow control is very simple since the memobj is blocking.

    panic_if(blockedPacket != nullptr, "Should never try to send if blocked!");

    // If we can't send the packet across the port, store it for later.
    if (!sendTimingReq(pkt)) {
        blockedPacket = pkt;
    }
}

bool
SimpleMemobj::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    // Just forward to the memobj.
    return owner->handleResponse(pkt);
}

void
SimpleMemobj::MemSidePort::recvReqRetry()
{
    // We should have a blocked packet if this function is called.
    assert(blockedPacket != nullptr);

    // Grab the blocked packet.
    PacketPtr pkt = blockedPacket;
    blockedPacket = nullptr;

    // Try to resend it. It's possible that it fails again.
    sendPacket(pkt);
}

void
SimpleMemobj::MemSidePort::recvRangeChange()
{
    owner->sendRangeChange();
}

bool
SimpleMemobj::handleRequest(PacketPtr pkt)
{
    if (blocked) {
        // There is currently an outstanding request. Stall.
        return false;
    }

    DPRINTF(SimpleMemobj, "Got request for addr %#x\n", pkt->getAddr());

    
    if (pkt -> cmd == MemCmd::WriteReq){
        
        printf("--------Write--------\n");
        printf("Addr: %#x\n", pkt->getAddr());
        std::string ss = "";
        for(int i=0 ; i < (pkt -> getSize()) ; i++) {
            
            for(int j=0 ; j<8 ; j++){
                // printf("%d", pkt -> getConstPtr<uint8_t>()[i] >> j & 1);
                ss = ss + std::__cxx11::to_string(pkt -> getConstPtr<uint8_t>()[i] >> j & 1);
            }
        }
        printf("Data: %s\n", ss.c_str());
        //encode data :)
        HammingCode hamming(ss);
        hamming.generate_code();
        printf("Encd: %s\n", hamming.get_code().c_str());

        // corrupt data before send to memory
        hamming.corrupt_code();
        std::string data = hamming.get_code();
        dmap[pkt->getAddr()] = data;

    }
    if (pkt -> cmd == MemCmd::ReadReq){
        if(dmap.find(pkt->getAddr()) != dmap.end()){
            printf("--------Read--------\n");
            printf("Addr: %#x\n", pkt->getAddr());
            printf("Data: %s\n", dmap[pkt->getAddr()].c_str());
            HammingCode hamming("");
            std::string correctData = hamming.correct_ham(dmap[pkt->getAddr()]);
            printf("Corr: %s\n", correctData.c_str());
            std::string decodedData = hamming.get_decode(correctData);
            printf("Decd: %s\n", decodedData.c_str());

            // wrtie in the specific format
            uint8_t *arr = new uint8_t[8];
            memset(arr, 0, 8*sizeof(uint8_t));
            for (size_t i = 0; i < decodedData.length() ; ++i) {
                char currentChar = decodedData[i];
                uint8_t bit = currentChar - '0';

                size_t index =  decodedData.length() - i - 1;
                size_t byteIndex = i / 8;
                size_t bitIndex = 7 - index % 8;
                arr[byteIndex] |= (bit << bitIndex);
                
            }
            
            pkt-> makeResponse();
            pkt->setData(arr);
            blocked = true;
            handleResponse(pkt);
            return true;
        }
    }

    // This memobj is now blocked waiting for the response to this packet.
    blocked = true;

    // Simply forward to the memory port
    memPort.sendPacket(pkt);

    return true;
}

bool
SimpleMemobj::handleResponse(PacketPtr pkt)
{
    assert(blocked);
    DPRINTF(SimpleMemobj, "Got response for addr %#x\n", pkt->getAddr());

    // The packet is now done. We're about to put it in the port, no need for
    // this object to continue to stall.
    // We need to free the resource before sending the packet in case the CPU
    // tries to send another request immediately (e.g., in the same callchain).
    blocked = false;

    // Simply forward to the memory port
    if (pkt->req->isInstFetch()) {
        instPort.sendPacket(pkt);
    } else {
        dataPort.sendPacket(pkt);
    }

    // For each of the cpu ports, if it needs to send a retry, it should do it
    // now since this memory object may be unblocked now.
    instPort.trySendRetry();
    dataPort.trySendRetry();

    return true;
}

void
SimpleMemobj::handleFunctional(PacketPtr pkt)
{
    // Just pass this on to the memory side to handle for now.
    memPort.sendFunctional(pkt);
}

AddrRangeList
SimpleMemobj::getAddrRanges() const
{
    DPRINTF(SimpleMemobj, "Sending new ranges\n");
    // Just use the same ranges as whatever is on the memory side.
    return memPort.getAddrRanges();
}

void
SimpleMemobj::sendRangeChange()
{
    instPort.sendRangeChange();
    dataPort.sendRangeChange();
}

} // namespace gem5
