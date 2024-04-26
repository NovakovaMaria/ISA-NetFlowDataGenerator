/*******************************************
* Mária Nováková, xnovak2w
* flow.cpp
* 14.11.2022
*******************************************/

#include "flow.h"

tv ts;

void setHeader(struct b5header *header){
    header->version = htons((u_int16_t)5);
    header->count = htons(1);
    header->SysUptime = htonl(ts.currentTime - ts.initialExportTime);
    header->unix_secs = htonl(ts.currentTimeSec);
    header->unix_nsecs = htonl(ts.currentTimeUsec);
    header->flow_sequence = htonl(numOfFlows);
    header->engine_id = 0;
    header->engine_type = 0;
    header->sampling_interval = 0;
}


void exportFlow(struct V5FlowRecord message){

    numOfFlows++;

    struct b5header header;
    setHeader(&header);

    // Putting packet together
    struct Flow flow;
    flow.header = header;
    flow.data = message;

    int sock;                        // socket descriptor
    int i;
    struct sockaddr_in server; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()
    char buffer[1024];     

    mempcpy(buffer, &flow, sizeof(flow));

    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;                   
    server.sin_port = htons(port);   

    if ((servent = gethostbyname(hostname.c_str())) == NULL){
        errx(1,"gethostbyname() failed\n");
    }

    memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 


    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1){
        err(1,"socket() failed\n");
    } 

    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1){ // connect to server
        err(1, "connect() failed");
    }

    i = send(sock,buffer,sizeof(flow),0);     // send data to the server
    
    if (i == -1){
        err(1,"send() failed");
    }else if (i != sizeof(flow)){
        err(1,"send(): buffer written partially");
    }

    if (sizeof(flow) == -1){
        err(1,"reading failed");
    }

    close(sock);
}


void TCP(const u_char *packet, u_int size_ip, vector<u_int32_t> *key, uint8_t *tcp_flag, u_int16_t *srcPort, u_int16_t *dstPort){
    const struct tcphdr *th;
    th = (struct tcphdr *) (packet + ETHER_SIZE + size_ip);
    // srcport and dstport for flow record
    *srcPort = ntohs(th->th_sport);
    *dstPort = ntohs(th->th_dport);

    // setting key
    key->push_back( (u_int32_t) ntohs(th->th_sport));
    key->push_back( (u_int32_t) ntohs(th->th_dport));

    // checking tcp flags
    if(th->th_flags & TH_RST || th->th_flags & TH_FIN){
        *tcp_flag = 1;
    }

}

void UDP(const u_char *packet, u_int size_ip, vector<u_int32_t> *key, u_int16_t *srcPort, u_int16_t *dstPort){
    const struct udphdr *uh;
    uh = (struct udphdr *) (packet + ETHER_SIZE + size_ip);
    // srcport and dstport for flow record
    *srcPort = ntohs(uh->uh_sport);
    *dstPort = ntohs(uh->uh_dport);

    // setting key
    key->push_back( (u_int32_t) ntohs(uh->uh_sport));
    key->push_back( (u_int32_t) ntohs(uh->uh_dport));
}

void ICMP(const u_char *packet, u_int size_ip,  vector<u_int32_t> *key, u_int16_t *srcPort, u_int16_t *dstPort){
    const struct icmphdr *ih;
    ih = (struct icmphdr *) (packet + ETHER_SIZE + size_ip);
    // srcport and dstport for flow record
    *srcPort = 0;
    *dstPort = (ih->type << 8)+ih->code;

    // setting key
    key->push_back(0);
    key->push_back( (u_int32_t) (ih->type << 8)+ih->code);
}

void keyGetPort(vector<u_int32_t> *key, uint8_t protocol, const u_char *packet, uint size_ip, uint8_t *tcp_flag,
                u_int16_t *srcPort, u_int16_t *dstPort){
    if(protocol == 6){ // protocol is tcp
        TCP(packet, size_ip, key, tcp_flag, srcPort, dstPort);
    }else if(protocol == 17){ // protocol is udp
        UDP(packet, size_ip, key, srcPort, dstPort);
    }else if(protocol == 1){ // protocol is icmp
        ICMP(packet, size_ip, key, srcPort, dstPort);
    }
}

void oldest(){
    auto it = mapF.begin(), old = mapF.begin();

    while(it != mapF.end()){
        // if current iterated packet has smaller time of last arrived packet, it is the oldest
        if(ntohl(old->second.Last) > ntohl(it->second.Last)){ 
            old = it;
        }
        it++;
    }
    // export the oldest
    exportFlow(old->second);
    // erase oldest
    mapF.erase(old);
}

void sizeOfFlow(uint8_t protocol, vector<u_int32_t> key, uint size_ip, uint size_ip_header){
    if(protocol == 17 || protocol == 1){
            // if protocol is udp or icmp substract size of header and ip header
            (mapF[key].dOctets) += htonl(ntohs(size_ip) - size_ip_header - 8);
    }else{
        // for tcp only substract ip header
        (mapF[key].dOctets) += htonl(ntohs(size_ip - size_ip_header));    
    }
}



void flows(const u_char *packet){
    const struct ip *ip;
    ip = (struct ip *) (packet + ETHER_SIZE);
    u_int size_ip = (ip->ip_hl & 0x0f)*4; //size of ip header
    
    vector<u_int32_t> key;
    uint8_t tcp_flag = 0;
    u_int16_t srcPort, dstPort;

    // process of making key (composed of source IP, destination IP, source Port, destination Port, ToS)
    key.push_back(ntohl(ip->ip_src.s_addr));
    key.push_back(ntohl(ip->ip_dst.s_addr));
    keyGetPort(&key, ip->ip_p, packet, size_ip, &tcp_flag, &srcPort, &dstPort );
    key.push_back((u_int32_t)ip->ip_tos);

    auto it = mapF.begin(); 
    bool erase = false;

    // checking active and inactive time for all of the flows in flow cache
    while(it != mapF.end()){
        auto timestamp = ts.currentTime - ts.initialExportTime;

        if((timestamp - ntohl(it->second.First)) >= active*1000){ //active export
            exportFlow(it->second);
            erase = true;
            mapF.erase(it++);
        }else if((timestamp - ntohl(it->second.Last)) >= inactive*1000){ //inactive export
            exportFlow(it->second);
            erase = true;
            mapF.erase(it++);
        }

        if(erase){
            erase = false;
        }else{
            ++it;
        }
    }


    if(mapF.count(key)){ // update flow
        mapF[key].Last = htonl(ts.currentTime - ts.initialExportTime);
        (mapF[key].dPkts) += htonl(1);
        sizeOfFlow(ip->ip_p, key, ip->ip_len, size_ip);

    }else{ //add new flow
        if(cache == mapF.size()){
            oldest();
        }

        mapF.insert({key, V5FlowRecord()});

        mapF[key].srcIP = ip->ip_src.s_addr;
        mapF[key].dstIP = ip->ip_dst.s_addr;
        mapF[key].nexthop = 0;
        mapF[key].input = 0;
        mapF[key].output = 0;
        mapF[key].dPkts = htonl(1);
        mapF[key].First = htonl(ts.currentTime - ts.initialExportTime); 
        mapF[key].Last = htonl(ts.currentTime - ts.initialExportTime); 
        mapF[key].tcp_flags = tcp_flag;
        mapF[key].prot = ip->ip_p;
        mapF[key].ToS = ip->ip_tos;
        mapF[key].dst_as = 0;
        mapF[key].src_as = 0;
        mapF[key].src_mask = 0;
        mapF[key].dst_mask = 0;
        sizeOfFlow(ip->ip_p, key, ip->ip_len, size_ip);
        mapF[key].srcPort = htons(srcPort);
        mapF[key].dstPort = htons(dstPort);
    }


    if(tcp_flag){ // export if fin or rst in tcp flag is set
        exportFlow(mapF[key]);
        mapF.erase(key);
    }
}

void callbackFunc(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){

    const struct ether_header* ethernet;
    ethernet = (struct ether_header *) packet;

    // updating current time of arrived packet
    ts.currentTime = header->ts.tv_sec*1000 + header->ts.tv_usec/1000;
    ts.currentTimeSec = header->ts.tv_sec;
    ts.currentTimeUsec = header->ts.tv_usec*1000;


    if(ts.initialExportTimeBool){
        ts.initialExportTime = ts.currentTime;
        ts.initialExportTimeBool = false;
    }

    flows(packet);

}


int main(int argc, char *argv[]){

    FILE *file;
    char *endptr, filename[100];
    int delimeter, pos = 2, c;

    struct bpf_program fp;
    pcap_t *handle;
    bpf_u_int32 net;
    

    // command line parsing
    while((c = getopt(argc, argv, "f:c:a:i:m:")) != -1){
        switch (c){
        case 'f':
            strcpy(filename, argv[pos]);
            stdin_input = false;
            break;
        case 'c':
            delimeter = (string(argv[pos])).find(":");
            if(delimeter == -1){
                ip = string(argv[pos]);
            }else{
                ip = string(argv[pos]).substr(0, delimeter);
                port = strtoull(string(argv[pos]).substr(delimeter + 1).c_str(), &endptr,10);
            }
            break;
        case 'a':
            active = strtoull(argv[pos], &endptr, 10);
            break;
        case 'i':
            inactive = strtoull(argv[pos], &endptr, 10);
            break;
        case 'm':
            cache = strtoull(argv[pos], &endptr, 10);
            break;
        default:
            break;
        }
        pos += 2;
    }

    // opening handler based on input
    if(!stdin_input){
        file = fopen(filename, "r");
        handle = pcap_fopen_offline(file, endptr);
    }else{
        handle = pcap_open_offline("-", endptr);
    }

    if (!handle){
        fprintf(stderr, "Cannot read file.\n");    
        return(2);
    }

    filter = FILTER;

    // trying to compile filter
    if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
        fprintf(stderr, "Cannot compile filter.\n");
        return(2);
    }
    
    // setting filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Cannot use filter.\n");
        return(2);
    }

    pcap_loop(handle, -1 ,callbackFunc, NULL);

    pcap_close(handle);

    // export all flows in flow cache
    if(!mapF.empty()){
        auto it = mapF.begin();
        while(it != mapF.end()){
            exportFlow(it->second);
            mapF.erase(it++);
        }
    }    

    printf("All exported flows: %u to %s\n", numOfFlows, hostname.c_str());
    return 0;
}
