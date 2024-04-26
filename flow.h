/*******************************************
* Mária Nováková, xnovak2w
* flow.h
* 14.11.2022
*******************************************/

#ifndef FLOW_H
#define FLOW_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include <cstring> 
#include <iostream>
#include <map>
#include <vector>
#include <err.h>
using namespace std;

#define __FAVOR_BSD
#include <pcap.h>
#define __FAVOR_BSD
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/ether.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#define __FAVOR_BSD
#include <netinet/ip_icmp.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#define __FAVOR_BSD
#include <netdb.h>

#define HOSTNAME "127.0.0.1:2055"
#define IP "127.0.0.1"
#define PORT 2055
#define ACT_TIMER 60
#define INACT_TIMER 10
#define COUNT 1024

#define ETHER_SIZE 14
#define ETHERTYPE_IP 0x0800
#define FILTER "tcp or udp or icmp"

/** @brief Flow cache
*/
map< vector<u_int32_t> , struct V5FlowRecord> mapF;

static int numOfFlows;
bool stdin_input = true;
unsigned int active = ACT_TIMER, inactive = INACT_TIMER, cache = COUNT, port = PORT; 
string hostname = IP, ip = "", filter;


/** @brief Struct for time management
 *
 *  @param currentTime current time of current read packet in ms
 *  @param currentTimeSec current time of current read packet in sec
 *  @param currentTimeUsec current time of current read packet in usec
 *  @param initialExportTime time of the very first packet = exporter boot time
 *  @param initialExportTimeBool bool variable used for setting initial exporter time
 */
typedef struct time_val{
    unsigned long currentTime = 0;
    unsigned long currentTimeSec = 0;
    unsigned long currentTimeUsec = 0;
    unsigned long initialExportTime = 0;
    bool initialExportTimeBool = true;
}tv;


/** @brief Struct of flow record.
 *
 *  @param srcIP        Source IP address
 *  @param dstIP        Destination IP address
 *  @param nexthop      IP address of next hop router
 *  @param input        SNMP index of input interface
 *  @param output       SNMP index of output interface
 *  @param dPkts        Packets in the flow
 *  @param dOctets      Total number of Layer 3 bytes in the packets of the flow
 *  @param First        SysUptime at start of flow
 *  @param Last         SysUptime at the time the last packet of the flow was received
 *  @param srcPort      TCP/UDP source port number or equivalent
 *  @param dstPort      TCP/UDP destination port number or equivalent
 *  @param pad1         Unused (zero) byte
 *  @param tcp_flags    Cumulative OR of TCP flags
 *  @param prot         IP protocol type
 *  @param ToS          IP type of service (ToS)
 *  @param src_as       Autonomous system number of the source, either origin or peer
 *  @param dst_as       Autonomous system number of the destination, either origin or peer
 *  @param src_mask     Source address prefix mask bits
 *  @param dst_mask     Destination address prefix mask bits
 *  @param pad2         Unused (zero) bytes
 */
struct V5FlowRecord{
    u_int32_t srcIP; 
    u_int32_t dstIP; 
    u_int32_t nexthop;
    u_int16_t input;
    u_int16_t output;
    u_int32_t dPkts;
    u_int32_t dOctets;
    u_int32_t First;
    u_int32_t Last;
    u_int16_t srcPort; 
    u_int16_t dstPort; 
    u_int8_t pad1 = 0;
    u_int8_t tcp_flags;
    u_int8_t prot;
    u_int8_t ToS; 
    u_int16_t src_as;
    u_int16_t dst_as;
    u_int8_t src_mask;
    u_int8_t dst_mask;
    u_int16_t pad2 = 0;
};

/** @brief Struct of flow header.
 *
 *  @param version          NetFlow export format version number
 *  @param count            Number of flows exported in this flow frame (protocol data unit, or PDU)
 *  @param SysUptime        Current time in milliseconds since the export device booted
 *  @param unix_secs        Current seconds since 0000 UTC 1970
 *  @param unix_nsecs       Residual nanoseconds since 0000 UTC 1970
 *  @param flow_sequence    Sequence counter of total flows seen
 *  @param reserved         Unused (zero) bytes
 */
struct b5header{
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence = 0;
    u_int8_t engine_type;
    u_int8_t engine_id;
    uint16_t sampling_interval;
};


/** @brief Struct of exporting flow.
 *
 *  @param header   header of packet
 *  @param data     flow record
 */
struct Flow{
    struct b5header header;
    //struct V5FLow data;
    struct V5FlowRecord data;
};

/** @brief Manipulates with flow cache.
 *
 *  @param packet   pacekt data
 *  @param key      vector with u_int32_t values used as key for map
 *  @return Void.
 */
void flows(const u_char *packet, vector<u_int32_t> *key);

/** @brief Call back function for pcap_loop().
 *
 *  @param args     optional customizable parameters
 *  @param header   packet header
 *  @param packet   pacekt = data
 *  @return Void.
 */
void callbackFunc(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);


/** @brief Computes dOctets parameter (lenght) of packet.
 *
 *  @param protocol     for protocol icmp and udp substrat size of header
 *  @param key          vector with u_int32_t values used as key for map
 *  @return Void.
 */

void sizeOfFlow(uint8_t protocol, vector<u_int32_t> key);

/** @brief Exports flows based on active and inactive time.
 *
 *  @return Void.
 */
void oldest();

/** @brief Computes dOctets parameter (lenght) of packet.
 *
 *  @param key      vector with u_int32_t values used as key for map
 *  @param protocol for protocol icmp and udp substrat size of header
 *  @param packet   pacekt = data
 *  @param size_ip  size of IP header
 *  @param tcp_flag used for exporting when fin or rst flag happens
 *  @param srcPort  source port
 *  @param dstPort  destination port
 *  @return Void.
 */
void keyGetPort(vector<u_int32_t> *key, uint8_t protocol, const u_char *packet, uint size_ip, uint8_t *tcp_flag,
                u_int16_t *srcPort, u_int16_t *dstPort);

/** @brief Sets parameters for header to export.
 *
 *  @param header header for flow packet for exporting
 *  @return Void.
 */              
void setHeader(struct b5header *header);

/** @brief Exports flow.
 *
 *  @param message flow record to be exported
 *  @return Void.
 */     
void exportFlow(struct V5FlowRecord message);

/** @brief Extract source and destination port number when packet has TCP protocol.
 *
 *  @param packet   pacekt = data from which port is extracted.
 *  @param size_ip  size of internet protocol part of the packet (for setting pointer to the right place of packet)
 *  @param key      vector with u_int32_t values used as key for map
 *  @param srcPort  source port
 *  @param dstPort  destination port
 *  @return Void.
 */
void TCP(const u_char *packet, u_int size_ip, vector<u_int32_t> *key, uint8_t *tcp_flag, u_int16_t *srcPort, u_int16_t *dstPort);

/** @brief Extract source and destination port number when packet has UDP protocol.
 *
 *  @param packet   pacekt = data from which port is extracted.
 *  @param size_ip  size of internet protocol part of the packet (for setting pointer to the right place of packet)
 *  @param key      vector with u_int32_t values used as key for map
 *  @param srcPort  source port
 *  @param dstPort  destination port
 *  @return Void.
 */
void UDP(const u_char *packet, u_int size_ip, vector<u_int32_t> *key, u_int16_t *srcPort, u_int16_t *dstPort);

/** @brief Computing destination port with icmp type and code
 *
 *  @param packet   pacekt = data from which port is extracted.
 *  @param size_ip  size of IP header, used for shifting
 *  @param key      vector with u_int32_t values used as key for map
 *  @param srcPort  source port
 *  @param dstPort  destination port
 *  @return Void.
 */
void ICMP(const u_char *packet, u_int size_ip,  vector<u_int32_t> *key, u_int16_t *srcPort, u_int16_t *dstPort);



#endif
