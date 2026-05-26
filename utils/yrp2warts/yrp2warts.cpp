/****************************************************************************
 * Copyright (c) 2016-2019 Justin P. Rohrer <jprohrer@tancad.org> 
 * Copyright (c) 2021-2022 Fahad Hilal <fhilal@mpi-inf.mpg.de>
 * All rights reserved.  
 *
 * Program:     $Id: yrp2warts.cpp $
 * Description: Convert Yarrp output files (https://www.cmand.org/yarrp) to 
 *              warts files (or text or json) (https://www.caida.org/tools/measurement/scamper/)
 *              indent -i4 -nfbs -sob -nut -ldi1 yrp2warts.cpp
 *
 * Attribution: R. Beverly, "Yarrp'ing the Internet: Randomized High-Speed 
 *              Active Topology Discovery", Proceedings of the ACM SIGCOMM 
 *              Internet Measurement Conference, November, 2016
 *
 * Attribution: F. Hilal, O. Gasser "Yarrpbox: Detecting middleboxes at 
 *              Internet Scale", Conference on emerging Networking 
 *              EXperiments and Technologies, December, 2023
 ***************************************************************************/
 
#include <unordered_map>
#include <sys/time.h>
#include <iomanip>
#include <memory>
#include "ipaddress.hpp"
#include "yarrpfile.hpp"
#include "json.hpp" 
extern "C" {
	#include "scamper_file.h"
	#include "scamper_addr.h"
	#include "scamper_list.h"
	#include "scamper_trace.h"
}

using ordered_json = nlohmann::ordered_json;
using namespace std;
using namespace ip;

string infile_name = "";
char * outfile_name;
FILE *out;
FILE **out_f;
bool read_stdin = false;
bool jsonOutput = false;

vector <string> jsonTcpModifs; // collect TCP field and option modificatons
vector <string> jsonTcpAdds; // collect TCP option additions 
vector <string> jsonTcpDels; // collect TCP option deletions
vector <string> jsonOptOrder;

uint16_t partialQuoteSize = 0;
uint8_t wsSet = 0;
uint8_t wsObserved = 0;

uint64_t lineNo = 0;

void usage(char *prog) {
	cout << "Usage:" << endl
		 << " $ " << prog << " -i input.yrp -o output.warts" << endl
		 << " $ bzip2 -dc input.yrp.bz2 | " << prog << " -s -o output.warts" << endl
		 << "  -i, --input             Input Yarrp file" << endl
		 << "  -j, --json              Generate JSON output (only for middlebox detection yarrp output file)" << endl
		 << "  -o, --output            Output Warts file (.warts) or text file or json file" << endl
		 << "  -s, --stdin             Read piped input from STIDN" << endl
		 << "  -h, --help              Show this message" << endl
		 << endl;
	exit(-1);
}

void parse_opts(int argc, char **argv) {
	if (argc <= 3) {
		usage(argv[0]);
	}
	char c;
	int opt_index = 1;
	while (opt_index < argc) {
		c = argv[opt_index][1];
		switch (c) {
		  case 'i':
			infile_name = argv[++opt_index];
			break;
		  case 'o':
			outfile_name = argv[++opt_index];
			break;
		  case 's':
			read_stdin = true;
			break;
		  case 'j':
		     jsonOutput = true;	
			 break;
		  case 'h':
		  default:
			usage(argv[0]);
		}
		opt_index++;
	}
}

struct yrpStats {
	ipaddress vantage_point;
	uint8_t tracetype;
	uint16_t maxttl;
	double t_min;
	double t_max;
};

struct hop {
	ipaddress addr;
	uint32_t sec;
	uint32_t usec;
	uint32_t rtt;
	uint16_t ipid;
	uint16_t psize;
	uint16_t rsize;
	uint8_t ttl;
	uint8_t rttl;
	uint8_t rtos;
	//uint16_t icmp_tc;
	uint8_t icmp_type;
	uint8_t icmp_code;
	//uint8_t hopflags = 0x10;
	//uint16_t probeSize; 
	uint8_t qTos;              
	uint32_t ipHashExtracted;
	uint32_t tcpHashExtracted;
	bool ipHashMatch;
	bool tcpHashMatch;
	bool completeHashMatch;
	bool badSequenceNumber;
	bool TosModif;
	bool pSizeModif;
	bool mssPresent;
	bool wsNotAdded;
	bool wsNotRemoved;
	uint8_t wsSet;
	uint8_t wsObserved;
    bool tmspPresent;
    bool mpCapablePresent;
    bool sackpPresent;
    bool nopNotPresent;
    bool goodMssData;
    bool goodMpCableData;
	bool goodTmspTsval;
	uint32_t qtmspTsvalObserved;
	bool optOrderModif;
    uint16_t firstOption;
    uint16_t secondOption;
    uint16_t thirdOption;
    uint16_t fourthOption;
    
	// IPv4 partial quote
	bool partialQt;

	uint16_t mssSet;
	uint16_t mssSeen;

	// IPv6 Header field modification indicators
	bool v6TcModif;
	bool v6FlowModif; 
	bool v6PlenModif; 
	bool v6DestModif;

	// UDP6 field mofification indicators
	bool spModif; 
	bool dpModif;
	bool UdpCksmModif; 
	bool UdpLenModif;
	
	// ICMPv6 field mofification indicators
	bool icmpTypeModif;
    bool icmpCodeModif;
    bool icmpIdModif;
    bool icmpSeqModif;

	// TCP field mofification indicators
	bool tcpSpModif;
    bool tcpDpModif;
    bool tcpSeqModif;
	bool tcpAckModif;
    bool tcpOffsetModif;
    bool tcpWindModif;
    bool tcpChksmModif;
    bool tcpUrgModif;
    bool tcpFlagsModif;
    bool tcpX2Modif;  

	// Field values
	uint8_t qTosSet;
    uint8_t qTosObserved;
    uint16_t qTotalLengthSet;
    uint16_t qTotalLengthObserved;
    uint16_t qDportSet;
    uint16_t qDportObserved;
    uint32_t qSeqSet;
    uint32_t qSeqObserved;
    uint32_t qAckSet;
    uint32_t qAckObserved;
    uint8_t qDoffSet;
    uint8_t qDoffObserved;
    uint8_t qX2Set;
    uint8_t qX2Observed;
    uint64_t qMpKeySet;
    uint64_t qMpKeyObserved;
    uint32_t qflowLabelSet;
    uint32_t qflowLabelObserved;
    uint8_t qTrafficClassSet;
    uint8_t qTrafficClassObserved;
    uint16_t qRcvWindowSet;
    uint16_t qRcvWindowObserved;
    uint16_t qUrgPtrSet;
    uint16_t qUrgPtrObserved;
    uint16_t qTCPCksmSet;
    uint16_t qTCPCksmObserved;
	uint16_t qUDPCksmSet;
    uint16_t qUDPCksmObserved;
    uint16_t qUDPLenSet;
    uint16_t qUDPLenObserved;
	uint8_t qICMPTypeSet;
    uint8_t qICMPTypeObserved;
    uint8_t qICMPCodeSet;
    uint8_t qICMPCodeObserved;
    uint16_t qICMPSeqSet;
    uint16_t qICMPSeqObs;

	hop& operator= (const yarrpRecord &r)
	{
		if(!detection) {
		  addr = r.hop;
		  sec = r.sec;
		  usec = r.usec;
		  rtt = r.rtt;
		  ipid = r.ipid;
		  psize = r.psize;
		  rsize = r.rsize;
		  ttl = r.ttl;
		  rttl = r.rttl;
		  rtos = r.rtos;
		//icmp_tc = 11;  // [TODO] FixMe
		  icmp_type = r.typ;
		  icmp_code = r.code;
		  return *this; 
		} else if(detection && traceType == "UDP6") {	
		  addr = r.hop;
		  sec = r.sec;
		  usec = r.usec;
		  rtt = r.rtt;
		  psize = r.psize;
		  rsize = r.rsize;
		  ttl = r.ttl;
		  rttl = r.rttl;
		  icmp_type = r.typ;
		  icmp_code = r.code;
		  v6TcModif = r.v6TcModif;
		  v6FlowModif = r.v6FlowModif;
		  v6PlenModif = r.v6PlenModif;
		  spModif = r.spModif;
		  dpModif = r.dpModif;
		  UdpCksmModif = r.UdpCksmModif;
		  UdpLenModif = r.UdpLenModif;
		  optOrderModif = false;

		  qflowLabelSet = r.qflowLabelSet;
		  qflowLabelObserved = r.qflowLabelObserved;
		  qTrafficClassSet = r.qTrafficClassSet;
		  qTrafficClassObserved = r.qTrafficClassObserved;
		  qTotalLengthSet = r.qTotalLengthSet; // works as payload length for IPv6
          qTotalLengthObserved = r.qTotalLengthObserved;
          qDportSet = r.qDportSet;
          qDportObserved = r.qDportObserved;
		  qUDPLenSet = r.qUDPLenSet;
		  qUDPLenObserved = r.qUDPLenObserved;
		  qUDPCksmSet = r.qUDPCksmSet;
		  qUDPCksmObserved = r.qUDPCksmObserved;
		  return *this;
		} else if(detection && traceType == "ICMP6") {
		  addr = r.hop;
		  sec = r.sec;
		  usec = r.usec;
		  rtt = r.rtt;
		  psize = r.psize;
		  rsize = r.rsize;
		  ttl = r.ttl;
		  rttl = r.rttl;
		  icmp_type = r.typ;
		  icmp_code = r.code;
		  v6TcModif = r.v6TcModif;
		  v6FlowModif = r.v6FlowModif;
		  v6PlenModif = r.v6PlenModif;
		  icmpTypeModif = r.icmpTypeModif;
		  icmpCodeModif = r.icmpCodeModif;
		  icmpIdModif = r.icmpIdModif;
		  icmpSeqModif = r.icmpSeqModif;
		  optOrderModif = false;
		  qflowLabelSet = r.qflowLabelSet;
		  qflowLabelObserved = r.qflowLabelObserved;
		  qTrafficClassSet = r.qTrafficClassSet;
		  qTrafficClassObserved = r.qTrafficClassObserved;
		  qTotalLengthSet = r.qTotalLengthSet; // works as payload length for IPv6
          qTotalLengthObserved = r.qTotalLengthObserved;
		  qICMPTypeSet = r.qICMPTypeSet;
		  qICMPTypeObserved = r.qICMPTypeObserved;
		  qICMPCodeSet = r.qICMPCodeSet;
		  qICMPCodeObserved = r.qICMPCodeObserved;
		  qICMPSeqSet = r.qICMPSeqSet;
		  qICMPSeqObs = r.qICMPSeqObs;
		  return *this;
		} else if(detection && (traceType == "TCP6_SYN" || traceType == "TCP6_ACK")) {
		  addr = r.hop;
		  sec = r.sec;
		  usec = r.usec;
		  rtt = r.rtt;
		  psize = r.psize;
		  rsize = r.rsize;
		  ttl = r.ttl;
		  rttl = r.rttl;
		  icmp_type = r.typ;
		  icmp_code = r.code;
		  v6TcModif = r.v6TcModif;
		  v6FlowModif = r.v6FlowModif;
		  v6PlenModif = r.v6PlenModif;
		  tcpSpModif = r.tcpSpModif;
		  tcpDpModif  = r.tcpDpModif;
          tcpSeqModif = r.tcpSeqModif;
		  tcpAckModif = r.tcpAckModif;
          tcpOffsetModif = r.tcpOffsetModif;
          tcpWindModif = r.tcpWindModif;
          tcpChksmModif = r.tcpChksmModif;
          tcpUrgModif = r.tcpUrgModif;
          tcpFlagsModif = r.tcpFlagsModif;
          tcpX2Modif = r.tcpX2Modif; 

		  mssSet = r.mssSet;
		  mssSeen = r.mssSeen;
		  mssPresent = r.mssPresent;
		  sackpPresent = r.sackpPresent;
		  mpCapablePresent = r.mpCapablePresent;
		  tmspPresent = r.tmspPresent;
		  goodMssData = r.goodMssData;
		  goodMpCableData = r.goodMpCableData;
		  goodTmspTsval = r.goodTmspTsval;
		  nopNotPresent = r.nopNotPresent;
          wsNotAdded = r.wsNotAdded;
		  wsNotRemoved = r.wsNotRemoved;
		  partialQt = r.partialQuote;   
                       
		  optOrderModif = r.optOrderModif;
		  firstOption = r.firstOption;
		  secondOption = r.secondOption;
		  thirdOption = r.thirdOption;
		  fourthOption =r.fourthOption;

          qflowLabelSet = r.qflowLabelSet;
		  qflowLabelObserved = r.qflowLabelObserved;
		  qTrafficClassSet = r.qTrafficClassSet;
		  qTrafficClassObserved = r.qTrafficClassObserved;
		  qTotalLengthSet = r.qTotalLengthSet; // works as payload length for IPv6
          qTotalLengthObserved = r.qTotalLengthObserved;
          qDportSet = r.qDportSet;
          qDportObserved = r.qDportObserved;
          qSeqSet = r.qSeqSet;
          qSeqObserved = r.qSeqObserved;
          qAckSet = r.qAckSet;
          qAckObserved = r.qAckObserved;
          qDoffSet = r.qDoffSet;
          qDoffObserved = r.qDoffObserved;
          qX2Set = r.qX2Set;
          qX2Observed = r.qX2Observed;
          qRcvWindowSet = r.qRcvWindowSet;
		  qRcvWindowObserved = r.qRcvWindowObserved;
		  qUrgPtrSet = r.qUrgPtrSet;
		  qUrgPtrObserved = r.qUrgPtrObserved;
		  qTCPCksmSet = r.qTCPCksmSet;
		  qTCPCksmObserved = r.qTCPCksmObserved;
		  qMpKeySet = r.qMpKeySet;
          qMpKeyObserved = r.qMpKeyObserved;

		  return *this;
		} else { 
		  addr = r.hop; 
		  ttl = r.ttl;
		  sec = r.sec;
		  usec = r.usec;
		  rtt = r.rtt;
		  ipid = r.ipid;
		  psize = r.psize;
		  rsize = r.rsize;
		  rttl = r.rttl;
		  icmp_type = r.typ;
		  icmp_code = r.code;
		  qTos = r.q_tos;
		  badSequenceNumber = r.badSeqNo;
		  TosModif = r.TosModif;
		  pSizeModif = r.pSizeModif;
	   	  tcpDpModif = r.tcpDpModif;
          tcpOffsetModif = r.tcpOffsetModif;
		  tcpFlagsModif = r.tcpFlagsModif;
		  tcpX2Modif = r.tcpX2Modif;   
		  ipHashExtracted = r.ipHashExtr;
		  tcpHashExtracted = r.tcpHashExtr;
		  ipHashMatch = r.ipMatch;
		  tcpHashMatch = r.tcpMatch;
		  completeHashMatch = r.completeMatch;
          mssSeen = r.mssSeen;
		  mssSet = r.mssSet;
   		  mssPresent = r.mssPresent;
		  sackpPresent = r.sackpPresent;
		  mpCapablePresent = r.mpCapablePresent;
		  tmspPresent = r.tmspPresent;
		  goodMssData = r.goodMssData;
		  goodMpCableData = r.goodMpCableData;
		  nopNotPresent = r.nopNotPresent;
	      wsNotAdded = r.wsNotAdded;
		  wsNotRemoved = r.wsNotRemoved;
		  wsSet = r.wsSet;
		  wsObserved = r.wsObserved;
    	  partialQt = r.partialQuote;
   		  optOrderModif = r.optOrderModif;
		  firstOption = r.firstOption;
		  secondOption = r.secondOption;
		  thirdOption = r.thirdOption;
		  fourthOption =r.fourthOption;
     	  qTosSet = r.qTosSet;
          qTosObserved = r.qTosObserved;
          qTotalLengthSet = r.qTotalLengthSet;
          qTotalLengthObserved = r.qTotalLengthObserved;
          qDportSet = r.qDportSet;
          qDportObserved = r.qDportObserved;
          qSeqSet = r.qSeqSet;
          qSeqObserved = r.qSeqObserved;
          qAckSet = r.qAckSet;
          qAckObserved = r.qAckObserved;
          qDoffSet = r.qDoffSet;
          qDoffObserved = r.qDoffObserved;
          qX2Set = r.qX2Set;
          qX2Observed = r.qX2Observed;
          qMpKeySet = r.qMpKeySet;
          qMpKeyObserved = r.qMpKeyObserved;
 		  qUrgPtrObserved = r.qUrgPtrObserved;
		  qRcvWindowObserved = r.qRcvWindowObserved;
		  qtmspTsvalObserved = r.qtmspTsvalObserved;
		return *this;
		}
	}
};

struct tcpFldsOpts {
   uint8_t ttl; 
   string hopIp;
   bool TosModif;
   bool pSizeModif; 
   bool badSeqNo;
   bool dpModif;
   bool offsetModif;
   bool flagsModif;
   bool x2Modif;
   string msg;  
   bool mssPresent; 
   bool sackpPresent;
   bool mpCapablePresent;
   bool tmspPresent;
   bool goodMssData;
   bool goodMpCapableData; 
   bool goodTmspTsval; 
   bool nopNotPresent; 
   bool wsNotAdded;
   bool wsNotRemoved;
   bool optOrderModif; 
   uint16_t firstOption;
   uint16_t secondOption; 
   uint16_t thirdOption; 
   uint16_t fourthOption;	
};

// For JSON file writing
struct jsonData {
	uint8_t ttl; 
    string hopIp;
	uint32_t rttl;
	uint32_t rtt;
	uint16_t ipid;
	uint8_t icmp_type;
	uint8_t icmp_code;
	bool optOrderModif;
	bool partialQt;
	uint16_t mssSet;
	uint16_t mssSeen;
	uint8_t wsSet;
	uint8_t wsObserved;
	uint16_t partialQuoteSize;
	uint16_t quoteSize;

	// Field values
	uint8_t qTosSet;
    uint8_t qTosObserved;
    uint16_t qTotalLengthSet;
    uint16_t qTotalLengthObserved;
    uint16_t qDportSet;
    uint16_t qDportObserved;
    uint32_t qSeqSet;
    uint32_t qSeqObserved;
    uint32_t qAckSet;
    uint32_t qAckObserved;
    uint8_t qDoffSet;
    uint8_t qDoffObserved;
    uint8_t qX2Set;
    uint8_t qX2Observed;
	uint32_t qtmspTsvalObserved;
    uint64_t qMpKeySet;
    uint64_t qMpKeyObserved;
    uint32_t qflowLabelSet;
    uint32_t qflowLabelObserved;
    uint8_t qTrafficClassSet;
    uint8_t qTrafficClassObserved;
    uint16_t qRcvWindowSet;
    uint16_t qRcvWindowObserved;
    uint16_t qUrgPtrSet;
    uint16_t qUrgPtrObserved;
    uint16_t qTCPCksmSet;
    uint16_t qTCPCksmObserved;
	uint16_t qUDPCksmSet;
    uint16_t qUDPCksmObserved;
    uint16_t qUDPLenSet;
    uint16_t qUDPLenObserved;
	uint8_t qICMPTypeSet;
    uint8_t qICMPTypeObserved;
    uint8_t qICMPCodeSet;
    uint8_t qICMPCodeObserved;
    uint16_t qICMPSeqSet;
    uint16_t qICMPSeqObs;
};

ostream& operator<< (ostream& os, const hop& h)
{
    return os << h.addr << " " << h.sec << " " << h.usec << " " << h.rtt << " " << h.ipid << " " << h.psize << " " << h.rsize << " " << uint16_t(h.ttl) << " " << uint16_t(h.rttl) << " " << uint16_t(h.rtos) << " " << uint16_t(h.icmp_type) << " " << uint16_t(h.icmp_code);	// << " " << uint16_t(h.hopflags);
}

bool operator<(const hop& h1, const hop& h2) {
	return h1.ttl < h2.ttl;
}

bool operator==(const hop& h1, const hop& h2) {
	return h1.ttl == h2.ttl;
}

scamper_addr* ip2scamper_addr(ipaddress &ip) {
	uint8_t sat = 0;
	void *addr;
	if (ip.version() == 4) {
		sat = SCAMPER_ADDR_TYPE_IPV4;
		//shared_ptr<uint32_t> ipv4 = ip.get4();
		//addr = ipv4.get();
		addr = ip.get4().get();
	}
	else if (ip.version() == 6) {
		sat = SCAMPER_ADDR_TYPE_IPV6;
		//shared_ptr<array<uint8_t,16> > ipv6 = ip.get6();
		//addr = ipv6.get();
		addr = ip.get6().get();
	}
	else {
		//cerr << ip << endl;
		cerr << "Not an IP address!" << endl;
		exit(1);
	}
	scamper_addr *sa;
	if ((sa = scamper_addr_alloc(sat, addr)) == NULL) {
		cerr << "Could not convert address!" << endl;
		exit(1);
	}
	//sa->type = ip.version();
	//sa->addr = ip.get().c_str();
	//sa->addr = &ip.get()[0];
	return sa;
}

yrpStats yarrp_proc(string yarrpfile, unordered_map<ipaddress, vector<hop> > &traces) {
	yarrpFile yrp;
	yarrpRecord r;
	yrpStats s;
	s.t_min = 0;
	s.t_max = 0;
	if (read_stdin) {
		if (!yrp.open(std::cin)) {
			cerr << "Failed to open input stream" << endl;
			exit(1);
		}
		std::cin.tie(nullptr);
	}
	else {
		if (!yrp.open(yarrpfile)) {
			cerr << "Failed to open input file: " << yarrpfile << endl;
			exit(1);
		}
	}
	double timestamp = 0.0;
	uint64_t yrp_count = 0;
	while (yrp.nextRecord(r)) {
		hop this_hop;
		this_hop = r;
		//traces[r.target][r.ttl] = this_hop;
		if (traces[r.target].size() < 255) {
			traces[r.target].push_back(this_hop);	// scamper_trace must be <= 255 hops long
		}
		if(!detection){
			timestamp = r.sec + (r.usec / 1000000.0);
		//timestamps[r.target] = timestamp;
		    if (s.t_min <= 0) { s.t_min = timestamp; }
		//if (s.t_max <= 0) { s.t_max = timestamps[r.target]; }
	        if (timestamp < s.t_min) { s.t_min = timestamp; }
	        if (timestamp > s.t_max) { s.t_max = timestamp; }
		}
		yrp_count++;
	
	}
	s.vantage_point = yrp.getSource();
	s.tracetype = yrp.getType();
	s.maxttl = yrp.getMaxTtl();
	cout << "Processed " << yrp_count << " Yarrp records" << endl;
	return s;
}

void useage ()
{
	cout << "$ ./yrp2warts <.yrp input file> <.warts output file>" << endl;
}

string opcodeToName(uint16_t *opcode) {
	string name;
	name.clear();
	if(*opcode == 2) {
		  name = "MSS ";
		  return name;
	} else if(*opcode == 4) {
		name = "Sack Permitted ";
		return name;
	} else if(*opcode == 30) {
		name = "MP Capable ";
		return name;
	} else if(*opcode == 8) {
		name = "Timestamp ";
		return name;
	}
	return NULL;
}

string jsonFormatString(string cut, string mainStr) {
	size_t loc = mainStr.find(cut);
	mainStr.erase(loc, cut.length());
	mainStr.erase(mainStr.begin()); // remove initial space
	mainStr.erase(mainStr.begin()); // remove staring :
	mainStr.erase(mainStr.end()-1); // remove final 2 spaces, one left by removing the cut string
	mainStr.erase(mainStr.end()-1);
    return mainStr;
}

string checkOptionsModifications(struct tcpFldsOpts *optData) {
	vector < pair <string, bool> > vect;
	string modifs;
	modifs.clear();
	jsonTcpAdds.clear();
	jsonTcpDels.clear();
	
	vect.push_back(make_pair(": TCP::MSS Removed ", optData->mssPresent));
	vect.push_back(make_pair(": TCP::Sack Permitted Removed ", optData->sackpPresent));
	vect.push_back(make_pair(": TCP::MP Capable Removed ", optData->mpCapablePresent));
	vect.push_back(make_pair(": TCP::Timestamp Removed ", optData->tmspPresent));
	vect.push_back(make_pair(": TCP::MSS Data Modified ", optData->goodMssData));
	vect.push_back(make_pair(": TCP::MP Capable Sender Key Modified ", optData->goodMpCapableData));
	if(traceType == "TCP6_SYN" || traceType == "TCP6_ACK")
	   vect.push_back(make_pair(": TCP::Timestamp TSVAL Modified ", optData->goodTmspTsval));
	
	vect.push_back(make_pair(": TCP::NOP Added ", optData->nopNotPresent));
	vect.push_back(make_pair(": TCP::Window Scale Added ", optData->wsNotAdded));
	vect.push_back(make_pair(": TCP::Window Scale Removed ", optData->wsNotRemoved));
	
	for(unsigned int i=0; i < vect.size(); i++) {
		if(!vect[i].second) {   
		   modifs = modifs + vect[i].first;
		   if(jsonOutput) {
			    string x = vect[i].first;
			    if(x.find("Modified") != string::npos) {
					x = jsonFormatString("Modified", x);
					jsonTcpModifs.push_back(x);					  
				} else if(x.find("Added")!= string::npos) {
				    x = jsonFormatString("Added", x);
					jsonTcpAdds.push_back(x);
  			    } else if(x.find("Removed") != string::npos) {
				    x = jsonFormatString("Removed", x);
					jsonTcpDels.push_back(x);
	     	    } 
	        }  
	    }
    }
	
	string optOrder;
	optOrder.clear();
	
	if(optData->optOrderModif) {
		optOrder = ": TCP::Option Order Modified - ";
        optOrder = optOrder + opcodeToName(&(optData->firstOption)) + opcodeToName(&(optData->secondOption)) + opcodeToName(&(optData->thirdOption)) + opcodeToName(&(optData->fourthOption));
		modifs = modifs + optOrder + " ";
		 
		if(jsonOutput) {
			jsonOptOrder.push_back(opcodeToName(&(optData->firstOption)));
			jsonOptOrder.push_back(opcodeToName(&(optData->secondOption)));
			jsonOptOrder.push_back(opcodeToName(&(optData->thirdOption)));
			jsonOptOrder.push_back(opcodeToName(&(optData->fourthOption)));
		}
	}
	return modifs;
}

// For IPv4 TCP
void checkFieldModifications(struct tcpFldsOpts *tcpData) {
	vector <pair <string, bool>> vect; 
	vect.push_back(make_pair(": IP::ToS ", tcpData->TosModif));
	vect.push_back(make_pair(": IP::Total Length ", tcpData->pSizeModif));
	vect.push_back(make_pair(": TCP::Sequence Number ", tcpData->badSeqNo));
	vect.push_back(make_pair(": TCP::Destination Port ", tcpData->dpModif));
	vect.push_back(make_pair(": TCP::Data Offset ", tcpData->offsetModif));
	vect.push_back(make_pair(": TCP::Flags ", tcpData->flagsModif));
	vect.push_back(make_pair(": TCP::Reserved ", tcpData->x2Modif));
	string fieldModifs;
	string optModifs;
	fieldModifs.clear();
	optModifs.clear();

	for(unsigned int i=0; i < vect.size(); i++) { 		
		if(vect[i].second) {
		    fieldModifs = fieldModifs + vect[i].first;
			if(jsonOutput) {
			    string s = vect[i].first;
		   	    s.erase(s.begin());
			    s.erase(s.begin());
			    s.erase(s.end()-1);
                jsonTcpModifs.push_back(s);      
			}		   
	    }
    }
	
	optModifs = checkOptionsModifications(tcpData);									  
	if(!jsonOutput) {
		tcpData->msg = tcpData->msg + optModifs;
		tcpData->msg = tcpData->msg + fieldModifs + "\n";
		char buff[500];
		snprintf(buff, 500, tcpData->msg.c_str(), tcpData->ttl, tcpData->hopIp.c_str());
		fprintf(*out_f,"%s", buff);	
	}									  
}

ordered_json create_Json(struct jsonData *jData, vector<string> &jModifs) {	 
	auto hop = ordered_json::object();
	hop["hop"] = jData->ttl;
	hop["from"] = jData->hopIp.c_str();
	if(traceType == "TCP_SYN" || traceType == "TCP_ACK" || traceType == "TCP6_SYN" || traceType == "TCP6_ACK") {
	    hop["Partial_Quote"] = jData->partialQt; 
		if(jData->partialQt)
		   hop["Quote_Size"] = partialQuoteSize;
		else
		   hop["Quote_Size"] = jData->quoteSize;  
	}
	if(traceType == "TCP_SYN" || traceType == "TCP_ACK") {
		if(jData->wsSet != jData->wsObserved) {
			hop["WS_Set"] = jData->wsSet;
     		hop["WS_Present"] = jData->wsObserved;
		}
		if(jData->qTosSet != jData->qTosObserved) {
			hop["ToS_Set"] = jData->qTosSet;		
			hop["ToS_Present"] = jData->qTosObserved;
		}
		if(jData->qTotalLengthSet != jData->qTotalLengthObserved) {
			hop["IP_TotalLength_Set"] = jData->qTotalLengthSet;
   		    hop["IP_TotalLength_Present"] = jData->qTotalLengthObserved;
	    }
		hop["IPID_Present"] = jData->ipid;
	}
	if(traceType == "TCP_SYN" || traceType == "TCP_ACK" || ((traceType == "TCP6_SYN" || traceType == "TCP6_ACK") and !jData->partialQt)) {
		if(jData->mssSet != jData->mssSeen) {
			hop["MSS_Set"] = jData->mssSet;
            hop["MSS_Present"] = jData->mssSeen;	
		}
		if(jData->qDportSet != jData->qDportObserved) {
			hop["Dst_Port_Set"] = jData->qDportSet;
  		    hop["Dst_Port_Present"] = jData->qDportObserved;
		}	 
		if(jData->qSeqSet != jData->qSeqObserved) {
			hop["Seq_Number_Set"] = jData->qSeqSet;
		    hop["Seq_Number_Present"] = jData->qSeqObserved;
		}
		if(jData->qAckSet != jData->qAckObserved) {
			hop["Ack_Number_set"] = jData->qAckSet;
  		    hop["Ack_Number_Present"] = jData->qAckObserved;
		}
		if(jData->qDoffSet != jData->qDoffObserved) {
			hop["Data_Offset_Set"] = jData->qDoffSet;
		    hop["Data_Offset_Present"] = jData->qDoffObserved;
		}
        if (jData->qX2Set != jData->qX2Observed) {
			hop["Reserved_Set"] = jData->qX2Set;
		    hop["Reserved_Present"] = jData->qX2Observed;
		} 
		if(jData->qMpKeySet != jData->qMpKeyObserved) {
			hop["MPCAPABLE_SKey_Set"] = jData->qMpKeySet;
     		hop["MPCAPABLE_SKey_Present"] = jData->qMpKeyObserved;
		}
		if(traceType == "TCP_SYN" || traceType == "TCP_ACK") {
			hop["Rcv_Window_Present"] = jData->qRcvWindowObserved;
		    hop["Urgent_Ptr_Present"] = jData->qUrgPtrObserved;
		}
	}
	if((traceType == "TCP6_SYN" || traceType == "TCP6_ACK") and !jData->partialQt) {
		if(jData->qRcvWindowSet != jData->qRcvWindowObserved) {
			hop["Rcv_Window_Set"] = jData->qRcvWindowSet;
 		    hop["Rcv_Window_Present"] = jData->qRcvWindowObserved;
		}
		if(jData->qUrgPtrSet != jData->qUrgPtrObserved) {
			hop["Urgent_Ptr_Set"] = jData->qUrgPtrSet;
		    hop["Urgent_Ptr_Present"] = jData->qUrgPtrObserved;
		} 
        if(jData->qTCPCksmSet != jData->qTCPCksmObserved) {
			hop["TCP_Checksum_Set"] = jData->qTCPCksmSet;
   		    hop["TCP_Checksum_Present"] = jData->qTCPCksmObserved;
		}
	}
	if((traceType == "TCP_SYN" || traceType == "TCP_ACK") and !jData->partialQt) {
		hop["Timestamp_TSVal_Present"] = jData->qtmspTsvalObserved;
	}
	if(traceType == "UDP6" || traceType == "ICMP6") {
	   	hop["Quote_Size"] = jData->quoteSize;
	    if(traceType == "UDP6") {
			if(jData->qUDPLenSet != jData->qUDPLenObserved) {
				hop["UDP_Length_Set"] = jData->qUDPLenSet;
	  		    hop["UDP_Length_Present"] = jData->qUDPLenObserved;
 			}
			if(jData->qUDPCksmSet != jData->qUDPCksmObserved) {
				hop["UDP_Checksum_Set"] = jData->qUDPCksmSet;
			    hop["UDP_Checksum_Present"] = jData->qUDPCksmObserved;
			}
		} else {
			if(jData->qICMPTypeSet != jData->qICMPTypeObserved) {
				hop["ICMP_Type_Set"] = jData->qICMPTypeSet;
			    hop["ICMP_Type_Present"] = jData->qICMPTypeObserved;
			}
            if(jData->qICMPCodeSet != jData->qICMPCodeObserved) {
				hop["ICMP_Code_Set"] = jData->qICMPCodeSet;
			    hop["ICMP_Code_Present"] = jData->qICMPCodeObserved;
			}
			if(jData->qICMPSeqSet != jData->qICMPSeqObs) {
				hop["ICMP_SequenceNumber_Set"] = jData->qICMPSeqSet;
  			    hop["ICMP_SequenceNumber_Present"] = jData->qICMPSeqObs;
			}
		}
	}
	if(traceType == "TCP6_SYN" || traceType == "TCP6_ACK" || traceType == "UDP6" || traceType == "ICMP6") {
		if(jData->qflowLabelSet != jData->qflowLabelObserved) {
			hop["Flow_Label_Set"] = jData->qflowLabelSet;
		    hop["Flow_Label_Present"] = jData->qflowLabelObserved;
		}
		if(jData->qTrafficClassSet != jData->qTrafficClassObserved) {
			hop["Traffic_Class_Set"] = jData->qTrafficClassSet;
		    hop["Traffic_Class_Present"] = jData->qTrafficClassObserved;
		}
		if(jData->qTotalLengthSet != jData->qTotalLengthObserved) {
			hop["IP_PayloadLength_Set"] = jData->qTotalLengthSet;
		    hop["IP_PayloadLength_Present"] = jData->qTotalLengthObserved; 
		}
	}	   
	hop["Reply_ttl"] = jData->rttl;
	hop["RTT"] = jData->rtt;
	hop["Code"] = jData->icmp_code;
	hop["Type"] = jData->icmp_type;
	hop["Modifications"] = jModifs;
	hop["Additions"] = jsonTcpAdds;
    hop["Deletions"] = jsonTcpDels;
	hop["Option_Order_Modified"] = jData->optOrderModif;
	hop["Option_Order"] = jsonOptOrder;
	 
	return hop;
}

int main(int argc, char* argv[]) {
	ios_base::sync_with_stdio(false);
	parse_opts(argc, argv);
	unordered_map<ipaddress, vector<hop> > traces;
	//unordered_map<ipaddress, double> timestamps;
	yrpStats stats = yarrp_proc(infile_name, traces);
	cout << "Created " << traces.size() << " traces" << endl;
	cout << "Opening output file " << outfile_name << endl;
	if (detection) {
		cout << "Middlebox Detection: "<< detection << endl;
		if (!outfile_name)
	      usage(argv[0]);
	    else {
		  out = fopen(outfile_name, "a");
		  out_f = &out;
	   }
	}

	scamper_file *outfile = NULL;
	scamper_cycle *cycle;
	scamper_list *list;
	uint64_t target_count = 0;
	uint8_t max_dup_ttl_cnt = 0;

	if(!detection) {
       if ((outfile = scamper_file_open(&outfile_name[0], 'w', (char *)"warts")) == NULL) {
		  cerr << "Failed to open output file: " << outfile_name << endl;
		  return -1;
	    }
	   //scamper_list *list = scamper_list_alloc(1, "yarrp", "yarrp list", "yarrp-1");
	   list = scamper_list_alloc(1, "yarrp", "yarrp list", "yarrp-1");
	   cout << "Writing cycle start" << endl;
	   //scamper_cycle *cycle = scamper_cycle_alloc(list);
	   cycle = scamper_cycle_alloc(list);
	   cycle->id = 1;
	   cycle->start_time = stats.t_min;
	   cycle->stop_time = stats.t_max;
	  //uint64_t target_count = 0;
	  //uint8_t max_dup_ttl_cnt = 0;
	   if (scamper_file_write_cycle_start(outfile, cycle) != 0) { return -1; }
	   //scamper_cycle_free(cycle);
	}

	if (detection && !ipv6 && !jsonOutput) {
		fprintf(*out_f, "** IP Hash: ToS + Destination IP + IPID + IP Total Length\n");
		fprintf(*out_f, "** Stored: Timestamp TSval\n\n");
		fprintf(*out_f, "** TCP Hash: Sequence Number + MSS Option + Sack_Permitted Option + MP_CAPABALE Option\n");
		fprintf(*out_f, "** Stored: Timestamp TSecr\n\n");
		fprintf(*out_f, "** Complete Hash: ToS + Destination IP + IPID + IP Total Length + Sequence Number + MSS Option + Sack_Permitted Option + MP_CAPABALE Option\n");
		fprintf(*out_f, "** Stored: Urgent Pointer + Receiver Window\n\n");
		fprintf(*out_f, "** Option Order: MSS Sack_Permitted MP_CAPABLE Timestamp\n\n");
	} 
	else if(detection && ipv6 && traceType == "UDP6" && !jsonOutput)
		fprintf(*out_f, "# IP version: 6\n# Trace type: UDP\n\n");
	else if(detection && ipv6 && traceType == "ICMP6" && !jsonOutput)
		fprintf(*out_f, "# IP version: 6\n# Trace type: ICMPv6\n\n");	
    else if(detection && ipv6 && traceType == "TCP6_SYN" && !jsonOutput)
		fprintf(*out_f, "# IP version: 6\n# Trace type: TCP SYN\n\n");
	else if(detection && ipv6 && traceType == "TCP6_ACK" && !jsonOutput)	
		fprintf(*out_f, "# IP version: 6\n# Trace type: TCP ACK\n\n");

    uint32_t pQuotesPerHop[1000] = {0}; // Count number of partial quotes at each hop number across all IPs
	for (unordered_map<ipaddress, vector<hop> >::iterator iter = traces.begin(); iter != traces.end(); ++iter) {
		ipaddress target = iter->first;
		vector<hop> hops = iter->second;
		sort(hops.begin(), hops.end());
		if(!detection){
			if (hops.size() > 255){
			hops.resize(255);	// scamper_trace can't write > 256 hops
		    }
		}
		/*if (hops.size() > 255){
			hops.resize(255);	// scamper_trace can't write > 256 hops
		}*/
		//vector<hop>::iterator thishop = unique(hops.begin(), hops.end());
		vector<hop>::iterator thishop = hops.begin();
		// hops.resize(distance(hops.begin(), thishop));
		uint16_t probehop;
		if (hops.size() > stats.maxttl) {
			probehop = hops.size();
		}
		else {
			probehop = stats.maxttl;
		}
		
	    double trace_timestamp = 0x1.fffffffffffffp+1023;
   	    struct timeval tv;
	    uint8_t last_ttl = 0;
	    uint16_t dup_ttl_cnt = 1;
		
		for (thishop = hops.begin(); thishop != hops.end(); ++thishop) {
			if (thishop->ttl > probehop) {
				probehop = thishop->ttl;
			}
			if (thishop->ttl == last_ttl) {
				dup_ttl_cnt++;
			}
			last_ttl = thishop->ttl;
			
			if(!detection){
			  double hop_timestamp = thishop->sec + (thishop->usec / 1000000.0);
			  if (hop_timestamp < trace_timestamp) {
				 trace_timestamp = hop_timestamp;
				 tv.tv_sec = thishop->sec;
				 tv.tv_usec = thishop->usec;
			  }
		    }
		}
		if (dup_ttl_cnt > max_dup_ttl_cnt) {
			max_dup_ttl_cnt = dup_ttl_cnt;
		}
		if (detection && !ipv6) {
			if(!jsonOutput){
			   fprintf(*out_f, "\n\n>> Yarrpbox to: %s\n", target.tostr().c_str());
			}
			uint8_t pQuoteCount = 0;
			vector <uint8_t> pQuoteHops;

			ordered_json j;
		    j["target"] = target.tostr().c_str();
			auto jHops = ordered_json::array();
			j["hops"] = jHops;
		  
		    for (thishop = hops.begin(); thishop != hops.end(); ++thishop) {
				jsonTcpModifs.clear(); 
			    jsonTcpAdds.clear();
			    jsonTcpDels.clear();
			    jsonOptOrder.clear();
			 
			    tcpFldsOpts data;
			    data.ttl = thishop->ttl;
			    data.hopIp = thishop->addr.tostr();
			    data.TosModif = thishop->TosModif;
			    data.pSizeModif = thishop->pSizeModif;
			    data.badSeqNo = thishop->badSequenceNumber;
			    data.dpModif = thishop->tcpDpModif;
			    data.offsetModif = thishop->tcpOffsetModif;
			    data.flagsModif = thishop->tcpFlagsModif;
			    data.x2Modif = thishop->tcpX2Modif;
			    data.mssPresent = thishop->mssPresent; 
			    data.sackpPresent = thishop->sackpPresent;
			    data.mpCapablePresent = thishop->mpCapablePresent;
			    data.tmspPresent = thishop->tmspPresent;
			    data.goodMssData = thishop->goodMssData;
			    data.goodMpCapableData = thishop->goodMpCableData;
			    data.goodTmspTsval = thishop->goodTmspTsval;
			    data.nopNotPresent = thishop->nopNotPresent;
			    data.wsNotAdded = thishop->wsNotAdded;
			    data.wsNotRemoved = thishop->wsNotRemoved;
			    data.optOrderModif = thishop->optOrderModif;
			    data.firstOption = thishop->firstOption;
			    data.secondOption = thishop->secondOption;
			    data.thirdOption = thishop->thirdOption;
			    data.fourthOption = thishop->fourthOption;
		
			    jsonData jData;
			    jData.ttl = thishop->ttl;
			    jData.hopIp = thishop->addr.tostr();
			    jData.optOrderModif = thishop->optOrderModif;
			    jData.mssSeen = thishop->mssSeen;
			    jData.mssSet = thishop->mssSet;
			    jData.wsSet = thishop->wsSet;
			    jData.wsObserved = thishop->wsObserved;
			    jData.rttl = thishop->rttl;
			    jData.rtt = thishop->rtt;
			    jData.ipid = thishop->ipid;
			    jData.partialQt = thishop->partialQt;
			    jData.quoteSize = thishop->rsize - (20 + 8);
			    jData.icmp_type = thishop->icmp_type;
			    jData.icmp_code = thishop->icmp_code;
			    jData.qTosSet = thishop->qTosSet;
                jData.qTosObserved = thishop->qTosObserved;
                jData.qTotalLengthSet = thishop->qTotalLengthSet;
                jData.qTotalLengthObserved = thishop->qTotalLengthObserved;
                jData.qDportSet = thishop->qDportSet;
                jData.qDportObserved = thishop->qDportObserved;
                jData.qSeqSet = thishop->qSeqSet;
                jData.qSeqObserved = thishop->qSeqObserved;
                jData.qAckSet = thishop->qAckSet;
                jData.qAckObserved = thishop->qAckObserved;
                jData.qDoffSet = thishop->qDoffSet;
                jData.qDoffObserved = thishop->qDoffObserved;
                jData.qX2Set = thishop->qX2Set;
                jData.qX2Observed = thishop->qX2Observed;
                jData.qMpKeySet = thishop->qMpKeySet;
                jData.qMpKeyObserved = thishop->qMpKeyObserved;
			    jData.qRcvWindowObserved = thishop->qRcvWindowObserved;
			    jData.qUrgPtrObserved = thishop->qUrgPtrObserved;
			    jData.qtmspTsvalObserved = thishop->qtmspTsvalObserved;

			    if(thishop->partialQt) {
					pQuoteCount++;
				    pQuoteHops.push_back(thishop->ttl);
				    pQuotesPerHop[thishop->ttl]++;
                 
				    string msg = "%-2d %-15s  Partial Quote ";
				    data.msg = msg;
				    checkFieldModifications(&data);
				    partialQuoteSize = thishop->rsize - 28; // IPv4 header  + ICMP header

				    if (jsonOutput){ 
						auto hop = create_Json(&jData, jsonTcpModifs);	
				        jHops.push_back(hop);
			            j["hops"] = jHops;
			  	    }
				    continue;
			    }
			 
			 // False/0 is change
			    if (thishop->ipHashExtracted == 0 && thishop->tcpHashExtracted == 0) {
					if(thishop->completeHashMatch) {
						if(!jsonOutput)
						    fprintf(*out_f, "%-2d %-15s  Timestamp::Removed or data set to 0\n",thishop->ttl, thishop->addr.tostr().c_str());
					    else{
							jsonTcpModifs.push_back("TCP:: Timestamp Zeroed/Removed");
					        auto hop = create_Json(&jData, jsonTcpModifs);
				            jHops.push_back(hop);
			                j["hops"] = jHops;
				        }
				    } else {
						string msg = "%-2d %-15s  Timestamp::Removed or data set to 0 : Complete hash::Modified ";
				        data.msg = msg;
				        checkFieldModifications(&data);
				  
				       if(jsonOutput) {
						    jsonTcpModifs.push_back("TCP:: Timestamp Zeroed/Removed");
					        jsonTcpModifs.push_back("Complete Hash");
					        auto hop = create_Json(&jData, jsonTcpModifs);
				            jHops.push_back(hop);
			                j["hops"] = jHops;
				        }
				    }
			    } else if((!thishop->ipHashMatch || !thishop->tcpHashMatch) && thishop->completeHashMatch) {
					if(!thishop->ipHashMatch) {
						if(!jsonOutput)
				            fprintf(*out_f, "%-2d %-15s  Timestamp::TSVal modified\n",thishop->ttl, thishop->addr.tostr().c_str());
				        else {
							jsonTcpModifs.push_back("TCP::Timestamp::TSVal");
					        auto hop = create_Json(&jData, jsonTcpModifs);
				            jHops.push_back(hop);
			                j["hops"] = jHops;
				        }  
				    } else if (!thishop->tcpHashMatch) {
						if(!jsonOutput)
				            fprintf(*out_f, "%-2d %-15s  Timestamp::Tsecr modified\n",thishop->ttl, thishop->addr.tostr().c_str()); 
				        else {
							jsonTcpModifs.push_back("TCP::Timestamp Tsecr"); 
					        auto hop = create_Json(&jData, jsonTcpModifs);
				            jHops.push_back(hop);
			                j["hops"] = jHops;
				        }    
				    }
			    } else if((thishop->ipHashMatch && thishop->tcpHashMatch) && !thishop->completeHashMatch) {
					if(!jsonOutput)
				        fprintf(*out_f, "%-2d %-15s  Receiver Window or Urgent Pointer::Modified\n",thishop->ttl, thishop->addr.tostr().c_str());
				    else {
						jsonTcpModifs.push_back("TCP::Urgent Pointer/Receiver Window");
					    auto hop = create_Json(&jData, jsonTcpModifs);
				        jHops.push_back(hop);
			            j["hops"] = jHops;
				    }	
			    } else if(!thishop->ipHashMatch && !thishop->tcpHashMatch && !thishop->completeHashMatch) {
					string msg = "%-2d %-15s  IP hash::Modified : TCP hash::Modified : Complete hash::Modified ";
				    data.msg = msg;
				    checkFieldModifications(&data);
				    if(jsonOutput){
						jsonTcpModifs.push_back("IP Hash");
					    jsonTcpModifs.push_back("TCP Hash"); 
					    jsonTcpModifs.push_back("Complete Hash");
					    auto hop = create_Json(&jData, jsonTcpModifs);
				        jHops.push_back(hop);
			            j["hops"] = jHops;
				    }
			    }
			    else if(!thishop->ipHashMatch && !thishop->completeHashMatch) {
					string msg = "%-2d %-15s  IP hash::Modified : Complete hash::Modified ";
				    data.msg = msg;
				    checkFieldModifications(&data);
				    if(jsonOutput) {
						jsonTcpModifs.push_back("IP Hash");
					    jsonTcpModifs.push_back("Complete Hash");
					    auto hop = create_Json(&jData, jsonTcpModifs);
				        jHops.push_back(hop);
			            j["hops"] = jHops;
				    }
			    } else if(!thishop->tcpHashMatch && !thishop->completeHashMatch) {
					string msg = "%-2d %-15s  TCP hash::Modified : Complete hash::Modified "; 
				    data.msg = msg;
				    checkFieldModifications(&data);
				    if(jsonOutput){
						jsonTcpModifs.push_back("TCP Hash");
					    jsonTcpModifs.push_back("Complete Hash");
					    auto hop = create_Json(&jData, jsonTcpModifs);
				        jHops.push_back(hop);
			            j["hops"] = jHops;
				    }
			    } else {
					if(!jsonOutput)
			           fprintf(*out_f, "%-2d %-15s \n",thishop->ttl, thishop->addr.tostr().c_str());
			        else if(jsonOutput) {
						auto hop = create_Json(&jData, jsonTcpModifs);
				        jHops.push_back(hop);
			            j["hops"] = jHops;
			        }
			    }
		    }
		    if(!jsonOutput) {
				fprintf(*out_f, "\n# Partial Quotes : %d\n", pQuoteCount);
		        fprintf(*out_f, "# Partial Quote hops : ");
		        for (uint8_t i = 0; i < pQuoteHops.size(); i++){
					fprintf(*out_f, "%d ", pQuoteHops[i]);
		        }
		    } else {
				j["Partial_Quote_Count"] = pQuoteCount;
		        std::ofstream o(outfile_name, ios_base::app); 
                //o << std::setw(4) << j << std::endl;
		        o << j << std::endl;
		    }
	    } else if(detection && ipv6 && traceType == "UDP6") {
			if(!jsonOutput) {
			   fprintf(*out_f, ">> Yarrpbox to: %s\n", target.tostr().c_str());
			}
			ordered_json j;
			j["target"] = target.tostr().c_str();
			auto jHops = ordered_json::array();
			j["hops"] = jHops;
			for (thishop = hops.begin(); thishop != hops.end(); ++thishop) {
				vector<string>jsonModifs;
				jsonModifs.clear();
				jsonTcpAdds.clear();
	            jsonTcpDels.clear();
				jsonOptOrder.clear();

				vector < pair <string, bool> > vect;
	            string modifs;
	            modifs.clear();
				 
	            vect.push_back(make_pair(": IP::Traffic Class ", thishop->v6TcModif));
	            vect.push_back(make_pair(": IP::Flow Label ", thishop->v6FlowModif));
	            vect.push_back(make_pair(": IP::Payload Length ", thishop->v6PlenModif));
	            vect.push_back(make_pair(": UDP::Source Port ", thishop->spModif));
	            vect.push_back(make_pair(": UDP::Destination Port ", thishop->dpModif));
				vect.push_back(make_pair(": UDP::Length ", thishop->UdpLenModif));
				vect.push_back(make_pair(": UDP::Checksum ", thishop->UdpCksmModif));

           	    for(unsigned int i=0; i < vect.size(); i++) {		
					if(vect[i].second) {
						modifs = modifs + vect[i].first;
				        if(jsonOutput){
							string s = vect[i].first;
					        s.erase(s.begin());
					        s.erase(s.begin());
					        s.erase(s.end()-1);
                            jsonModifs.push_back(s);      
					    }
		            }
	            }
			    jsonData jData;
			    jData.ttl = thishop->ttl;
			    jData.hopIp = thishop->addr.tostr();
			    jData.rttl = thishop->rttl;
			    jData.rtt = thishop->rtt;
			    jData.partialQt = thishop->partialQt;
			    jData.quoteSize = thishop->rsize - 8;
			    jData.icmp_type = thishop->icmp_type;
			    jData.icmp_code = thishop->icmp_code;
			    jData.qflowLabelSet = thishop->qflowLabelSet;
			    jData.qflowLabelObserved = thishop->qflowLabelObserved;
			    jData.qTrafficClassSet = thishop->qTrafficClassSet;
			    jData.qTrafficClassObserved = thishop->qTrafficClassObserved;
			    jData.qTotalLengthSet = thishop->qTotalLengthSet;
                jData.qTotalLengthObserved = thishop->qTotalLengthObserved;
                jData.qDportSet = thishop->qDportSet;
                jData.qDportObserved = thishop->qDportObserved;
                jData.qUDPLenSet = thishop->qUDPLenSet;
			    jData.qUDPLenObserved = thishop->qUDPLenObserved;
			    jData.qUDPCksmSet = thishop->qUDPCksmSet;
			    jData.qUDPCksmObserved = thishop->qUDPCksmObserved;

			    if(jsonOutput) {
					auto hop = create_Json(&jData, jsonModifs);
				    jHops.push_back(hop);
			        j["hops"] = jHops;
			    } else {  
					string msg = "%-2d %-39s ";
			        msg = msg + modifs + "\n";
			        char buff[500];
			        snprintf(buff, 500, msg.c_str(), thishop->ttl, thishop->addr.tostr().c_str());
			        fprintf(*out_f,"%s", buff);
			    }
			}
			if(jsonOutput) {
				std::ofstream o(outfile_name, ios_base::app); 
                //o << std::setw(4) << j << std::endl;
				o << j << std::endl;
			}
		} else if(detection && ipv6 && traceType == "ICMP6") {
			if(!jsonOutput) {
				fprintf(*out_f, ">> Yarrpbox to: %s\n", target.tostr().c_str());
			}
			
			ordered_json j;
			j["target"] = target.tostr().c_str();
			auto jHops = ordered_json::array();
			j["hops"] = jHops;
			
			for (thishop = hops.begin(); thishop != hops.end(); ++thishop) {
				vector<string>jsonModifs;
				jsonModifs.clear();
				jsonTcpAdds.clear();
	            jsonTcpDels.clear();
				jsonOptOrder.clear();
				 
				vector < pair <string, bool> > vect;
	            string modifs;
	            modifs.clear();
				
	            vect.push_back(make_pair(": IP::Traffic Class ", thishop->v6TcModif));
	            vect.push_back(make_pair(": IP::Flow Label ", thishop->v6FlowModif));
	            vect.push_back(make_pair(": IP::Payload Length ", thishop->v6PlenModif));
	            vect.push_back(make_pair(": ICMP::Type ", thishop->icmpTypeModif));
	            vect.push_back(make_pair(": ICMP::Code ", thishop->icmpCodeModif));
				vect.push_back(make_pair(": ICMP::Identifier ", thishop->icmpIdModif));
				vect.push_back(make_pair(": ICMP::Sequence No ", thishop->icmpSeqModif));
				 
           	    for(unsigned int i=0; i < vect.size(); i++) {		
					if(vect[i].second) {
						modifs = modifs + vect[i].first;
                        // remove ": " and space at the end 
					    if(jsonOutput) {
							string s = vect[i].first;
					        s.erase(s.begin());
					        s.erase(s.begin());
					        s.erase(s.end()-1);
                            jsonModifs.push_back(s);      
					    }
		            }
	            }
			    jsonData jData;
			    jData.ttl = thishop->ttl;
			    jData.hopIp = thishop->addr.tostr();
			    jData.rttl = thishop->rttl;
			    jData.rtt = thishop->rtt;
			    jData.optOrderModif = thishop->optOrderModif; 
			    jData.partialQt = thishop->partialQt;
			    jData.quoteSize = thishop->rsize - 8;
			    jData.icmp_type = thishop->icmp_type;
			    jData.icmp_code = thishop->icmp_code;
			    jData.qflowLabelSet = thishop->qflowLabelSet;
			    jData.qflowLabelObserved = thishop->qflowLabelObserved;
			    jData.qTrafficClassSet = thishop->qTrafficClassSet;
			    jData.qTrafficClassObserved = thishop->qTrafficClassObserved;
			    jData.qTotalLengthSet = thishop->qTotalLengthSet;
                jData.qTotalLengthObserved = thishop->qTotalLengthObserved;
			    jData.qICMPTypeSet = thishop->qICMPTypeSet; 
			    jData.qICMPTypeObserved = thishop->qICMPTypeSet;
			    jData.qICMPCodeSet = thishop->qICMPCodeSet;
			    jData.qICMPCodeObserved = thishop->qICMPCodeObserved;
			    jData.qICMPSeqSet = thishop->qICMPSeqSet;
			    jData.qICMPSeqObs = thishop->qICMPSeqObs;

			    if(jsonOutput) {
					auto hop = create_Json(&jData, jsonModifs);
				    jHops.push_back(hop);
			        j["hops"] = jHops;
			    } else { 
				   string msg = "%-2d %-39s ";
			       msg = msg + modifs + "\n";
			       char buff[500];
			       snprintf(buff, 500, msg.c_str(), thishop->ttl, thishop->addr.tostr().c_str());
			       fprintf(*out_f,"%s", buff);
			    }
			}
			if(jsonOutput) {
				std::ofstream o(outfile_name, ios_base::app); 
                //o << std::setw(4) << j << std::endl;
				o << j << std::endl;
			}			 
		}
		else if(detection && ipv6 && (traceType == "TCP6_SYN" || traceType == "TCP6_ACK")) {
			if(!jsonOutput) {
				fprintf(*out_f, ">> Yarrpbox to: %s\n", target.tostr().c_str());
			}
			ordered_json j;
			j["target"] = target.tostr().c_str();
			auto jHops = ordered_json::array();
		    j["hops"] = jHops;
			uint8_t pQuoteCount = 0;
			for (thishop = hops.begin(); thishop != hops.end(); ++thishop) {
				jsonTcpModifs.clear(); 
				vector <pair <string, bool> > vect;
	            string modifs;
				string optModifs;
	            modifs.clear();
				optModifs.clear();
				jsonOptOrder.clear();

				tcpFldsOpts data;
			    data.ttl = thishop->ttl;
			    data.hopIp = thishop->addr.tostr();
			    data.mssPresent = thishop->mssPresent; 
			    data.sackpPresent = thishop->sackpPresent;
			    data.mpCapablePresent = thishop->mpCapablePresent;
			    data.tmspPresent = thishop->tmspPresent;
			    data.goodMssData = thishop->goodMssData;
			    data.goodMpCapableData = thishop->goodMpCableData;
			    data.goodTmspTsval = thishop->goodTmspTsval;
			    data.nopNotPresent = thishop->nopNotPresent;
			    data.wsNotAdded = thishop->wsNotAdded;
			    data.wsNotRemoved = thishop->wsNotRemoved;
				data.optOrderModif = thishop->optOrderModif;
			    data.firstOption = thishop->firstOption;
			    data.secondOption = thishop->secondOption;
			    data.thirdOption = thishop->thirdOption;
			    data.fourthOption = thishop->fourthOption;
				 
				jsonData jData;
			    jData.ttl = thishop->ttl;
			    jData.hopIp = thishop->addr.tostr();
			    jData.rttl = thishop->rttl;
			    jData.rtt = thishop->rtt;
		    	jData.optOrderModif = thishop->optOrderModif; 
			    jData.mssSeen = thishop->mssSeen;
			    jData.mssSet = thishop->mssSet;
			    jData.wsSet = thishop->wsSet;
			    jData.wsObserved = thishop->wsObserved;
			    jData.partialQt = thishop->partialQt;
				jData.quoteSize = thishop->rsize - 8;
				jData.icmp_type = thishop->icmp_type;
			    jData.icmp_code = thishop->icmp_code;
				jData.qflowLabelSet = thishop->qflowLabelSet;
				jData.qflowLabelObserved = thishop->qflowLabelObserved;
				jData.qTrafficClassSet = thishop->qTrafficClassSet;
				jData.qTrafficClassObserved = thishop->qTrafficClassObserved;
				jData.qTotalLengthSet = thishop->qTotalLengthSet;
                jData.qTotalLengthObserved = thishop->qTotalLengthObserved;
                jData.qDportSet = thishop->qDportSet;
                jData.qDportObserved = thishop->qDportObserved;
                jData.qSeqSet = thishop->qSeqSet;
                jData.qSeqObserved = thishop->qSeqObserved;
                jData.qAckSet = thishop->qAckSet;
                jData.qAckObserved = thishop->qAckObserved;
                jData.qDoffSet = thishop->qDoffSet;
                jData.qDoffObserved = thishop->qDoffObserved;
                jData.qX2Set = thishop->qX2Set;
                jData.qX2Observed = thishop->qX2Observed;
				jData.qRcvWindowSet = thishop->qRcvWindowSet;
				jData.qRcvWindowObserved = thishop->qRcvWindowObserved;
				jData.qUrgPtrSet = thishop->qUrgPtrSet;
				jData.qUrgPtrObserved = thishop->qUrgPtrObserved;
				jData.qTCPCksmSet = thishop->qTCPCksmSet;
				jData.qTCPCksmObserved = thishop->qTCPCksmObserved;
                jData.qMpKeySet = thishop->qMpKeySet;
                jData.qMpKeyObserved = thishop->qMpKeyObserved;

				if(thishop->partialQt) {
					pQuoteCount++;
					partialQuoteSize = thishop->rsize - 8;
				    if(!jsonOutput) {
					   fprintf(*out_f, "%-2d %-39s  Partial Quote\n", thishop->ttl, thishop->addr.tostr().c_str()); 
				    } else {
					   auto hop = create_Json(&jData, jsonTcpModifs);
				       jHops.push_back(hop);
			           j["hops"] = jHops;
				    }
				    continue;
			    }
				
	            vect.push_back(make_pair(": IP::Traffic Class ", thishop->v6TcModif));
	            vect.push_back(make_pair(": IP::Flow Label ", thishop->v6FlowModif));
	            vect.push_back(make_pair(": IP::Payload Length ", thishop->v6PlenModif));
				vect.push_back(make_pair(": TCP::Source Port ", thishop->tcpSpModif));
				vect.push_back(make_pair(": TCP::Dst Port ", thishop->tcpDpModif));
				vect.push_back(make_pair(": TCP::Sequence Number ", thishop->tcpSeqModif));
				vect.push_back(make_pair(": TCP::Acknowledgement Number ", thishop->tcpAckModif));
				vect.push_back(make_pair(": TCP::Data Offset ", thishop->tcpOffsetModif));
				vect.push_back(make_pair(": TCP::Rcv Window ", thishop->tcpWindModif));
				vect.push_back(make_pair(": TCP::Checksum ", thishop->tcpChksmModif));
				vect.push_back(make_pair(": TCP::Urgent Pointer ", thishop->tcpUrgModif));
				vect.push_back(make_pair(": TCP::Flags ", thishop->tcpFlagsModif));
				vect.push_back(make_pair(": TCP::Reserved ", thishop->tcpX2Modif));

            	for(unsigned int i=0; i < vect.size(); i++) {		
					if(vect[i].second){
						modifs = modifs + vect[i].first;
                        if(jsonOutput) {
							string s = vect[i].first;
					        s.erase(s.begin());
					        s.erase(s.begin());
					        s.erase(s.end()-1);
                            jsonTcpModifs.push_back(s);      
					    }
		            }
	            }
			    string msg = "%-2d %-39s ";
			    msg = msg + modifs;
			    data.msg = msg;
			    optModifs = checkOptionsModifications(&data);

			    if(jsonOutput) {
					auto hop = create_Json(&jData, jsonTcpModifs);
				    jHops.push_back(hop);
			        j["hops"] = jHops;
			    } else {
				    msg = msg + optModifs + "\n";
			        char buff[500];
			        snprintf(buff, 500, msg.c_str(), thishop->ttl, thishop->addr.tostr().c_str());
			        fprintf(*out_f,"%s", buff);
				}
			}
			if(!jsonOutput) {
				fprintf(*out_f, "\n# Partial Quotes : %d\n", pQuoteCount);
	     	} else {
			    j["Partial_Quote_Count"] = pQuoteCount;
			    std::ofstream o(outfile_name, ios_base::app); 
                //o << std::setw(4) << j << std::endl;
			    o << j << std::endl;
		    } 
		}
        
		// Warts file writing for standard yarrp operation
		scamper_trace *trace = scamper_trace_alloc();
		if(!detection){
			//scamper_trace *trace = scamper_trace_alloc();
		    trace->list = list;
		    //trace->cycle = cycle;
		    trace->src = ip2scamper_addr(stats.vantage_point);
		    trace->dst = ip2scamper_addr(target);
		    //double ts = timestamps[target];
		    //cout << setprecision (17) << ts << endl;
		    trace->start = tv;
		    trace->hop_count = probehop;
		    trace->probec = stats.maxttl;
		    trace->type = stats.tracetype;
		    trace->attempts = 1;
		    trace->firsthop = 1;
		    trace->sport = 1234;
		    trace->dport = 80;
		    //cout << "Allocating trace" << endl;
		    scamper_trace_hops_alloc(trace, probehop);
		    uint16_t hopcnt = 0;
		    for (vector<hop>::iterator thishop = hops.begin(); thishop != hops.end(); ++thishop) {
			    trace->hops[hopcnt] = scamper_trace_hop_alloc();
			    trace->hops[hopcnt]->hop_addr = ip2scamper_addr(thishop->addr);
			    struct timeval rttv;
			    rttv.tv_sec = (uint32_t) (thishop->rtt / 1000000.0);
			    rttv.tv_usec = thishop->rtt - (rttv.tv_sec * 1000000);
			    trace->hops[hopcnt]->hop_rtt = rttv;
			    //trace->hops[hopcnt]->hop_flags = thishop.hopflags;
			    trace->hops[hopcnt]->hop_flags = 0x10;
			    trace->hops[hopcnt]->hop_probe_id = 0;
			    trace->hops[hopcnt]->hop_probe_ttl = thishop->ttl;
			    trace->hops[hopcnt]->hop_probe_size = thishop->psize;
			    trace->hops[hopcnt]->hop_reply_ttl = thishop->rttl;
			    trace->hops[hopcnt]->hop_reply_tos = thishop->rtos;
			    trace->hops[hopcnt]->hop_reply_size = thishop->rsize;
			    trace->hops[hopcnt]->hop_reply_ipid = thishop->ipid;
			    trace->hops[hopcnt]->hop_icmp_type = thishop->icmp_type;
			    trace->hops[hopcnt]->hop_icmp_code = thishop->icmp_code;
			    hopcnt++;
		    }
		}
		if(!detection)
		  if (scamper_file_write_trace(outfile, trace) != 0) { return -1; }
		target_count++;
		
		if (detection && !jsonOutput)
		   fprintf(*out_f, "\n\n");
	}
	if(detection && (traceType == "TCP_SYN" || traceType == "TCP_ACK") && !jsonOutput) {
		fprintf(*out_f, "\n\n");
		for (uint8_t j = 1; j < 33; j++) {
			fprintf(*out_f, "** Partial quotes from  hop %d: %d\n", j, pQuotesPerHop[j]);
		}
	}
	cout << "Writing cycle stop" << endl;
    if(!detection)
	    if (scamper_file_write_cycle_stop(outfile, cycle) != 0) { return -1; }
	return 0;
}
