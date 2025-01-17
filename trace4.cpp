/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"
#include "options.h"
#include "xxhash32.h"

uint16_t mssAssigned = 0;

uint32_t computeHash(string hash_input, struct tcphdr_options *tcp_o, bool wsSet, unsigned char* wS) {
    unsigned char * option_start = (unsigned char *)tcp_o;
    option_start = option_start + 20;
    string option_string;
    while(*option_start != tcp_o->th_tmsp.kind) {
        option_string = option_string + to_string(*option_start);
        hash_input = hash_input + to_string(*option_start);
        ++option_start;
    }
        
    // Going over 3 bytes of wscale option if it was set by us
    if (wsSet)
        hash_input = hash_input + to_string(*wS) + to_string(*(wS + 1)) + to_string(*(wS + 2)); 
        
    char *hash_begin = (char*) hash_input.c_str();
    uint32_t hash_complete = XXHash32::hash(hash_begin, hash_input.size(), 0);  
    hash_input.clear();
    //option_string.clear();
    return hash_complete;
}

Traceroute4::Traceroute4(YarrpConfig *_config, Stats *_stats) : Traceroute(_config, _stats) {
    memset(&source, 0, sizeof(struct sockaddr_in)); 
    if (config->probesrc) {
        source.sin_family = AF_INET;
        if (inet_pton(AF_INET, config->probesrc, &source.sin_addr) != 1)
          fatal("** Bad source address.");
        cout << ">> Using IP source: " << config->probesrc << endl;
    } else {
        infer_my_ip(&source);
    }
    inet_ntop(AF_INET, &source.sin_addr, addrstr, INET_ADDRSTRLEN);
    config->set("SourceIP", addrstr, true);
    mssAssigned = config->mssData;
    payloadlen = 0;
    outip = (struct ip *)calloc(1, PKTSIZE);
    outip->ip_v = IPVERSION;
    outip->ip_hl = sizeof(struct ip) >> 2;
    outip->ip_src.s_addr = source.sin_addr.s_addr;
    if (config->testing)
       return;
    sndsock = raw_sock(&source);
    if (config->probe and config->receive) {
        lock();   /* grab mutex; make listener thread block. */
        pthread_create(&recv_thread, NULL, listener, this);
    }
}

Traceroute4::~Traceroute4() {
    free(outip);
}

void Traceroute4::probePrint(struct in_addr *targ, int ttl) {
    uint32_t diff = elapsed();
    if (config->probesrc)
        cout << inet_ntoa(source.sin_addr) << " -> ";
    cout << inet_ntoa(*targ) << " ttl: ";
    cout << ttl;
    if (config->instance)
        cout << " i=" << (int) config->instance;
    cout << " t=" << diff;
    (config->coarse) ? cout << "ms" << endl : cout << "us" << endl;
}

void
Traceroute4::probe(const char *targ, int ttl) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    inet_aton(targ, &(target.sin_addr));
    probe(&target, ttl);
}

void
Traceroute4::probe(uint32_t addr, int ttl) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    target.sin_addr.s_addr = addr;
    probe(&target, ttl);
}

void
Traceroute4::probe(struct sockaddr_in *target, int ttl) {
    outip->ip_ttl = ttl;
    outip->ip_id = htons(ttl + (config->instance << 8));
    outip->ip_off = 0; // htons(IP_DF);
    outip->ip_dst.s_addr = (target->sin_addr).s_addr;
    outip->ip_sum = 0;
    if (TR_UDP == config->type) {
        probeUDP(target, ttl);
    } else if ( (TR_ICMP == config->type) || (TR_ICMP_REPLY == config->type) ) {
        probeICMP(target, ttl);
    } else if ( (TR_TCP_SYN == config->type) || (TR_TCP_ACK == config->type) ) {
        probeTCP(target, ttl);
    } else {
        cerr << "** bad trace type:" << config->type << endl;
        assert(false);
    }
}

void
Traceroute4::probeUDP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct udphdr *udp = (struct udphdr *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + sizeof(struct udphdr));

    uint32_t diff = elapsed();
    payloadlen = 2;
    /* encode MSB of timestamp in UDP payload length */ 
    if (diff >> 16)
        payloadlen += (diff>>16);
    if (verbosity > HIGH) {
        cout << ">> UDP probe: ";
        probePrint(&target->sin_addr, ttl);
    }

    packlen = sizeof(struct ip) + sizeof(struct udphdr) + payloadlen;

    outip->ip_p = IPPROTO_UDP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = IP_DF;
#else
    outip->ip_len = htons(packlen);
    outip->ip_off = ntohs(IP_DF);
#endif
    /* encode destination IPv4 address as cksum(ipdst) */
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    udp->uh_sport = htons(dport);
    udp->uh_dport = htons(dstport);
    udp->uh_ulen = htons(sizeof(struct udphdr) + payloadlen);
    udp->uh_sum = 0;

    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* compute UDP checksum */
    memset(data, 0, 2);
    u_short len = sizeof(struct udphdr) + payloadlen;
    udp->uh_sum = p_cksum(outip, (u_short *) udp, len);

    /* encode LSB of timestamp in checksum */
    uint16_t crafted_cksum = diff & 0xFFFF;
    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(udp->uh_sum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    udp->uh_sum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> UDP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

void
Traceroute4::probeTCP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    
    struct tcphdr_options *tcp_o;
    struct tcphdr *tcp; 

    /* encode destination IPv4 address as cksum(ipdst) */
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    
    /* encode send time into seq no as elapsed milliseconds */
    uint32_t diff = elapsed();

    if(!config->midbox_detection) {
        tcp = (struct tcphdr *)(ptr + (outip->ip_hl << 2));   
        // In middlebox detection mode, use length of header with options
        packlen = sizeof(struct ip) + sizeof(struct tcphdr) + payloadlen;
     
        /* encode destination IPv4 address as cksum(ipdst) */
        //uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    
        tcp->th_sport = htons(dport);
        tcp->th_dport = htons(dstport);
    
        if (verbosity > HIGH) {
            cout << ">> TCP probe: ";
            probePrint(&target->sin_addr, ttl);
        }

        tcp->th_seq = htonl(diff);
        tcp->th_off = 5;
        tcp->th_win = htons(0xFFFE);
        tcp->th_sum = 0;
        /* don't want to set SYN, lest we be tagged as SYN flood. */
        if (TR_TCP_SYN == config->type) {
            tcp->th_flags |= TH_SYN;
        } else {
           tcp->th_flags |= TH_ACK;
           tcp->th_ack = htonl(target->sin_addr.s_addr);
        }
    } else {
        tcp_o = (struct tcphdr_options *)(ptr + (outip->ip_hl << 2));
        if(config->wScaleProvided)
          packlen = sizeof(struct ip) + sizeof(struct tcphdr_options) + sizeof(struct window_scale) + 1 + payloadlen; //1 for EoOL
        else
          packlen = sizeof(struct ip) + sizeof(struct tcphdr_options) + payloadlen;
        
        tcp_o->tcp.th_sport = htons(dport);
        tcp_o->tcp.th_dport = htons(dstport);
    
        if(verbosity > HIGH) {
            cout << ">> TCP probe: ";
            probePrint(&target->sin_addr, ttl);
        }
        if(config->fixSequenceNo)
           tcp_o->tcp.th_seq = htonl(1);
        else   
           tcp_o->tcp.th_seq = htonl(diff); 
       
        if(config->wScaleProvided)
           tcp_o->tcp.th_off = 13;
        else
           tcp_o->tcp.th_off = 12; 
       
        tcp_o->tcp.th_ack = htonl(0);
        tcp_o->tcp.th_win = htons(0xFFFE); 
        tcp_o->tcp.th_sum = 0;
        tcp_o->tcp.th_urp = htons(0xFFFE); 
        tcp_o->tcp.th_x2 = TCP_RESERVED_SET;

        tcp_o->th_mss.kind = TCPOPT_MSS;
        tcp_o->th_mss.len  = TCPOLEN_MSS;
        tcp_o->th_mss.data = htons(mssAssigned); 

        tcp_o->th_sackp.kind = TCPOPT_SACK_PERM;
        tcp_o->th_sackp.len  = TCPOLEN_SACK_PERM;

        tcp_o->th_mpc.kind = TCPOPT_MPTCP; 
        tcp_o->th_mpc.len  = 12;
        tcp_o->th_mpc.flag = 0x01;
        tcp_o->th_mpc.sender_key = __bswap_64(MPCAPABLE_SENDER_KEY_SET);

        tcp_o->th_tmsp.kind = TCPOPT_TIMESTAMP;
        tcp_o->th_tmsp.len  = TCPOLEN_TIMESTAMP;

        if (config->wScaleProvided) {
            struct window_scale *ws = (struct window_scale *) (ptr + (outip->ip_hl << 2) + sizeof(struct tcphdr_options));
            ws->kind = TCPOPT_WINDOW;
            ws->len = TCPOLEN_WINDOW;
           ws->shift = config->wScale;
        }

       /* don't want to set SYN, lest we be tagged as SYN flood. */
        if (TR_TCP_SYN == config->type) {
            tcp_o->tcp.th_flags |= TH_SYN;
        } else {
           tcp_o->tcp.th_flags |= TH_ACK;
           if(!config->midbox_detection)
              tcp_o->tcp.th_ack = htonl(target->sin_addr.s_addr);
        }
    }
    outip->ip_p = IPPROTO_TCP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif

    /*
     * explicitly computing cksum probably not required on most machines
     * these days as offloaded by OS or NIC.  but we'll be safe.
     */
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));
   
    /*
     * bsd rawsock requires host ordered len and offset; rewrite here as
     * chksum must be over htons() versions
     */
    /*u_short len = sizeof(struct tcphdr) + payloadlen;
      tcp->th_sum = p_cksum(outip, (u_short *) tcp, len);
    */
    
    if(!config->midbox_detection) {
        u_short len = sizeof(struct tcphdr) + payloadlen;
        tcp->th_sum = p_cksum(outip, (u_short *) tcp, len);
    } else {
        // Compute Complete hash
        char dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(outip->ip_dst), dst, INET_ADDRSTRLEN);
        string dstIP(dst); 

        string hash_input = to_string(outip->ip_tos) + dstIP + to_string(outip->ip_id) + to_string(htons(packlen)) + to_string(tcp_o->tcp.th_seq);
        uint32_t completeHash = 0;
        if(config-> wScaleProvided){
           unsigned char* wsBegin = ptr + (outip->ip_hl << 2) + sizeof(struct tcphdr_options);
           completeHash = computeHash(hash_input, tcp_o, config->wScaleProvided, wsBegin);
        } else
           completeHash = computeHash(hash_input, tcp_o, config->wScaleProvided, NULL);

        tcp_o->tcp.th_urp = htons(completeHash & 0x0000FFFF); // Lower 2 bytes in urgent pointer
        tcp_o->tcp.th_win = htons((completeHash >>16) & 0x0000FFFF); // Upper byte in receiver window
        
        uint32_t check = uint32_t((ntohl( tcp_o->tcp.th_urp << 16) + ntohl((tcp_o->tcp.th_win ))));
    
        // Compute partial hash 1 (IP hash)
        string partial_hash1_input = to_string(outip->ip_tos) + dstIP + to_string(outip->ip_id) + to_string(htons(packlen));
        unsigned char *hash_begin = (unsigned char*) partial_hash1_input.c_str();
        uint32_t partial_hash1 = XXHash32::hash(hash_begin, partial_hash1_input.size(),0); 
        tcp_o->th_tmsp.TSval = htonl(partial_hash1);
        
        // Compute partial hash 2 (TCP Hash)
        string partial_hash2_input = to_string (tcp_o->tcp.th_seq);
        uint32_t partialHash2 = 0;
        if(config-> wScaleProvided) {
           unsigned char* wsBegin = ptr + (outip->ip_hl << 2) + sizeof(struct tcphdr_options);
           partialHash2 = computeHash(partial_hash2_input, tcp_o, config->wScaleProvided, wsBegin);
        } else
           partialHash2 = computeHash(partial_hash2_input, tcp_o, config->wScaleProvided, NULL);
        
        tcp_o->th_tmsp.TSecr = htonl(partialHash2);
        
        u_short len = 0;
        if(config->wScaleProvided)
          len = sizeof(struct tcphdr_options) + sizeof(struct window_scale) + 1 + payloadlen;
        else
          len = sizeof(struct tcphdr_options) + payloadlen;
       
       tcp_o->tcp.th_sum = p_cksum(outip, (u_short *) tcp_o, len);
    }

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

void
Traceroute4::probeICMP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct icmp *icmp = (struct icmp *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + ICMP_MINLEN);

    payloadlen = 2;
    packlen = sizeof(struct ip) + ICMP_MINLEN + payloadlen;
    outip->ip_p = IPPROTO_ICMP;
    outip->ip_len = htons(packlen);
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif
    /* encode send time into icmp id and seq as elapsed milli/micro seconds */
    uint32_t diff = elapsed();
    if (verbosity > HIGH) {
        cout << ">> ICMP probe: ";
        probePrint(&target->sin_addr, ttl);
    }
    icmp->icmp_type = ICMP_ECHO;
    if (TR_ICMP_REPLY == config->type)
        icmp->icmp_type = ICMP_ECHOREPLY;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = htons(diff & 0xFFFF);
    icmp->icmp_seq = htons((diff >> 16) & 0xFFFF);
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* compute ICMP checksum */
    memset(data, 0, 2);
    u_short len = ICMP_MINLEN + payloadlen;
    icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

    /* encode cksum(ipdst) into checksum */
    uint16_t crafted_cksum = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(icmp->icmp_cksum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    icmp->icmp_cksum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> ICMP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

