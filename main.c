#include <stdio.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>
#include <time.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <Iphlpapi.h>
#include <malloc.h>
#include <math.h>
#include "StructPacket.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#define INFINITE_PING_FLAG 1
#define DF_FLAG 16384
#define ARGV_N 11
#define ARGV_L 12
#define ARGV_TOS 13
#define ARGV_IVAL 14
#define ARGV_TTL 15
#define ARGV_SID 16
#define ARGV_SN 17
#define ARGV_W 18
#define ARGV_HELP 19
#define DEFAULT_TIMEOUT 4

int str_to_int(char * str);
int argv_parser(char *);
void error_exit(char * error);
void usage(char *name);
int CtrlHandler(DWORD fdwCtrlType);
u_short cksum(u_short *ip, int len);
void printStat();
void type_code_decoder(int type, int code);
char *getTos(int tos);
void minmaxTime(int tm);

//Initial values
int pktCount = 4, timeSum = 0, jitterSum = 0, minTime = -1, maxTime = 0, avgTime, sucessRcvPkt = 0, faultRcvPkt = 0;
char tosStr[6];


int main(int argc, char *argv[]) {

    u_long netDstAddr = 0, netBestRoute, netSrcAddr;
    char *strDstAddr = NULL;
    char *hostName;
    char *progName;
    int pktSize = 100, tos = 0, ttl = 128, sid, sn=1, timeout = DEFAULT_TIMEOUT, interval = 1000; //Default value
    u_short flags = 0;
    int i; //For loops

    WSADATA wsaData;
    int dwError;
    struct hostent *hstruct;
    struct in_addr addr;

    time_t t;
    srand(time(&t));
    sid = rand() % 65535;

    WSAStartup(MAKEWORD(2,2),&wsaData);

    progName = *argv++; argc--;//Go through program name


    /*Argument parser*/
    while(argc--)
    {       
        switch(argv_parser(*argv))
        {
            case INFINITE_PING_FLAG:
                flags = flags | INFINITE_PING_FLAG;
                break;
            case DF_FLAG:
                flags = flags | DF_FLAG;
                break;
            case ARGV_N:
                argc--;
                if(argc < 0)
                    error_exit("Wrong arguments\n");
                argv++;
                if((pktCount = str_to_int(*argv)) == 0)
                    return -1;
                break;
            case ARGV_L:
                argc--;
                if(argc < 0)
                    error_exit("Wrong arguments\n");
                argv++;
                if((pktSize = str_to_int(*argv)) == 0)
                    return -1;
                if(pktSize <= 64 || pktSize > 1500)
                    error_exit("64 < [packet size] < 1500\n");
                break;
            case ARGV_TOS:
                argc--;
                if(argc < 0)
                    error_exit("Wrong arguments\n");
                argv++;
                if((tos = str_to_int(*argv)) == 0)
                    return -1;
                break;

            case ARGV_TTL:
                argc--;
                if(argc < 0)
                    error_exit("Wrong arguments\n");
                argv++;
                if((ttl = str_to_int(*argv)) == 0)
                    return -1;
                break;

            case ARGV_SID:
                argc--;
                if(argc < 0)
                    error_exit("Wrong arguments\n");
                argv++;
                if((sid = str_to_int(*argv)) == 0)
                    return -1;
                break;

            case ARGV_W:
                argc--;
                if(argc < 0)
                    error_exit("Wrong arguments\n");
                argv++;
                if((timeout = str_to_int(*argv)) == 0)
                    return -1;
                break;

            case ARGV_SN:
                argc--;
                if(argc < 0)
                    error_exit("Wrong arguments\n");
                argv++;
                if((sn = str_to_int(*argv)) == 0)
                    return -1;
                break;

            case ARGV_IVAL:
                argc--;
                if(argc < 0)
                    error_exit("Wrong arguments\n");
                argv++;
                interval = str_to_int(*argv);
                break;

            case ARGV_HELP:
                usage(progName);
                return 1;

            default:
                if(strDstAddr != NULL || *argv[0] == '-')
                    error_exit("Unknown parametr. Use --help to see all options\n");

                /*Get target ip address*/
                hostName = *argv;
                hstruct = gethostbyname(*argv);
                if(hstruct == NULL)
                {
                    dwError = WSAGetLastError();
                    if (dwError == WSAHOST_NOT_FOUND)
                    {
                        printf("%s: Host not found\n", *argv);
                    }else{
                        printf("Unknown error\n");
                    }
                    return -1;
                }else{
                    netDstAddr = *(u_long *) hstruct->h_addr_list[0];
                    addr.S_un.S_addr = netDstAddr;
                    strDstAddr = inet_ntoa(addr);
                }
                break;
        }
        argv++;
    }
    if(netDstAddr == 0)
    {
        usage(progName);
        return 0;
    }
    //printf("addr:%s cnt:%d pktSize:%d flags:%d\n",strDstAddr, pktCount, pktSize, flags);


    /*Find route*/
    MIB_IPFORWARDROW pMib;
    if(GetBestRoute(netDstAddr, 0, &pMib))
        error_exit("Fail to get route\n");

    if(pMib.dwForwardType == 3)
        netBestRoute = netDstAddr;
    else
        netBestRoute = (u_long) pMib.dwForwardNextHop;


    /*Get aproptiate network adapter*/
    PIP_ADAPTER_INFO pAdapterInfo;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    DWORD dwRetVal = 0;

    pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL)
        error_exit("Error allocating memory needed to call GetAdaptersinfo\n");

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        FREE(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(ulOutBufLen);
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        FREE(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(ulOutBufLen);
        if (pAdapterInfo == NULL)
            error_exit("Error allocating memory needed to call GetAdaptersinfo\n");
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        while (pAdapterInfo) {
            if(pAdapterInfo->Index == pMib.dwForwardIfIndex)
                break;
            pAdapterInfo = pAdapterInfo->Next;
        }
    }

    if(pAdapterInfo->Type != MIB_IF_TYPE_ETHERNET)
        error_exit("Ethernet interface only\n");

    netSrcAddr = inet_addr(pAdapterInfo->IpAddressList.IpAddress.String);

    /* Check function src mac
    BYTE *dstMacAddr = pAdapterInfo->Address;
    int y;
    for(y = 0; y < pAdapterInfo->AddressLength ; y++)
        printf("%0x:",*(dstMacAddr+y));

    printf("\n");
    */

    /*Open network adapter*/
    pcap_if_t *alldevs, *d;
    pcap_addr_t *a;
    pcap_t *fsend, *frecv;
    struct bpf_program fcode;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ext = 0;

    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }


    /*Get apropriate network adapter for pcap*/
    for(d=alldevs; d; d=d->next)
    {
        for(a = d->addresses;a;a=a->next)
        {
            if(a->addr)
            {                
                if(((struct sockaddr_in *)a->addr)->sin_addr.s_addr == netSrcAddr)
                {                    
                    ext = 1;
                    break;
                }
            }
        }
        if(ext)
            break;
    }

    if(d == NULL)
        error_exit("Can't find apropriate adapter\n");

    if((fsend = pcap_open(d->name, 65536, 0, 1000, NULL, errbuf)) == NULL)
        error_exit("Failed to open network adpter\n");

    if((frecv = pcap_open(d->name, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL, 1, NULL, errbuf)) == NULL)
        error_exit("Failed to open network adpter\n");

    if (pcap_compile(frecv, &fcode, "icmp", 1, 0) < 0)
    {
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(frecv, &fcode) < 0)
    {
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs);


    /*Get dst mac address*/
    ULONG dstMacAddr[2];
    ULONG PhysAddrLen = 6;

    dstMacAddr[0] = dstMacAddr[1] = 0;

    dwRetVal = SendARP(netBestRoute,0,dstMacAddr,&PhysAddrLen);
    if(dwRetVal != NO_ERROR)
        error_exit("Failed to get destination mac\n");

    /*  Check function
    int y;
    BYTE *bt = (BYTE *) dstMacAddr;
    for(y = 0;y<PhysAddrLen; y++)
    {
        printf("%.2x:",*(bt+y));
    }
    printf("\n");
    */



    /*Make packet*/
    const u_char *pPktSnd, *pPktRcv;
    eth_header *pEthHdrSnd, *pEthHdrRcv;
    ip_header *pIpHdrSnd, *pIpHdrRcv;
    icmp_header *pIcmpHdrSnd, *pIcmpHdrRcv;

    if((pPktSnd = (u_char *) calloc(1,pktSize)) == NULL)
        return 1;

    pEthHdrSnd = (eth_header *) pPktSnd;
    pIpHdrSnd = (ip_header *) (pPktSnd + sizeof(eth_header));
    pIcmpHdrSnd = (icmp_header *) (pPktSnd + sizeof(eth_header) + sizeof(ip_header));

    /*Headers filling*/
    pEthHdrSnd->type = 0x8;
    /*Dst mac*/
    u_char *bt = (u_char *) dstMacAddr;
    u_char *eAddr = (u_char *) &(pEthHdrSnd->dst_1);
    for(i=0;i<6;i++)
        *(eAddr+i) = *(bt+i);

    /*Src mac*/
    bt = (u_char *) pAdapterInfo->Address;
    eAddr = (u_char *) &(pEthHdrSnd->src_1);
    for(i=0;i<6;i++)
        *(eAddr+i) = *(bt+i);

    /*IP header*/
    pIpHdrSnd->ver_ihl = 0x45;
    pIpHdrSnd->tlen = htons(pktSize-sizeof(eth_header));
    pIpHdrSnd->proto = 0x1; //ICMP
    pIpHdrSnd->ttl = ttl;
    pIpHdrSnd->tos = tos;
    pIpHdrSnd->flags_fo = htons(pIpHdrSnd->flags_fo | (flags & DF_FLAG));
    pIpHdrSnd->identification = htons(rand() % 65535);

    u_long *saddr = (u_long *) &(pIpHdrSnd->saddr);
    u_long *daddr = (u_long *) &(pIpHdrSnd->daddr);
    *saddr = netSrcAddr;
    *daddr = netDstAddr;

    /*ICMP Header*/
    pIcmpHdrSnd->type = 8;
    pIcmpHdrSnd->code = 0;
    pIcmpHdrSnd->sn = sn;
    pIcmpHdrSnd->sid = sid;

    /*Checksum calculate*/
    pIpHdrSnd->crc = cksum((u_short *)pIpHdrSnd,sizeof(ip_header));
    pIcmpHdrSnd->crc = cksum((u_short *)pIcmpHdrSnd,pktSize-(sizeof(eth_header) + sizeof(ip_header)));
    
    /*Register control handler function for ctrl+c, ctrl+pause keys*/
    if(SetConsoleCtrlHandler( (PHANDLER_ROUTINE) CtrlHandler, 1) == 0)
        error_exit("Unable to set ctrl handler\n");



    /*Main loop*/
    struct pcap_pkthdr *header;
    int loop = 1, res, type, code;
    char *rcvAddr;
    u_long diffTime, sndTimeS, sndTimeU, rcvTimeS, rcvTimeU, prvPktTime=0;
    u_long jitter;
    time_t sndTime, rcvTime;

    if(flags&INFINITE_PING_FLAG)
        loop = 0;

    printf("\nPing for %s [%s]:\n\n", hostName, strDstAddr);
    while(pktCount)
    {
        time(&sndTime);

        if (pcap_sendpacket(fsend, pPktSnd, pktSize) != 0)
        {
            printf("\nError sending the packet: %s\n", pcap_geterr(fsend));
            return -1;
        }

        /*Reciving ourself request packet to get time of sending */
        while((res = pcap_next_ex(frecv, &header, &pPktRcv)) >= 0)
        {
            if(res == 0)
                        // Timeout elapsed
                        continue;
            pEthHdrRcv = (eth_header *) pPktRcv;
            pIpHdrRcv = (ip_header *) (pPktRcv + sizeof(eth_header));
            pIcmpHdrRcv = (icmp_header *) (pPktRcv + sizeof(eth_header) + sizeof(ip_header));
            if(pIpHdrRcv->identification == pIpHdrSnd->identification)
            {
                sndTimeS = header->ts.tv_sec; sndTimeU = header->ts.tv_usec;
                break;
            }
        }

        /*Waiting for reply*/
        while((res = pcap_next_ex(frecv, &header, &pPktRcv)) >= 0)
        {
            time(&rcvTime);
            if(rcvTime-sndTime > timeout)
            {
                printf("Timeout\n");
                faultRcvPkt++;
                break;
            }
            if(res == 0)
                        // Timeout elapsed
                        continue;

            pIpHdrRcv = (ip_header *) (pPktRcv + sizeof(eth_header));
            pIcmpHdrRcv = (icmp_header *) (pPktRcv + sizeof(eth_header) + sizeof(ip_header));
            if(pIcmpHdrRcv->type == 0 &&\
                    pIcmpHdrRcv->code == 0 &&\
                    pIcmpHdrRcv->sid == pIcmpHdrSnd->sid && \
                    pIcmpHdrRcv->sn == pIcmpHdrSnd->sn)
            {
                rcvTimeS = header->ts.tv_sec; rcvTimeU = header->ts.tv_usec;
                diffTime = (((rcvTimeS - sndTimeS) * 1000000 + rcvTimeU) - sndTimeU)/1000;
                jitter = diffTime - prvPktTime;
                jitterSum += abs(jitter);
                prvPktTime = diffTime;
                minmaxTime(diffTime);
                printf("%d bytes icmp_seq=%d ttl=%d rtt=%dms jitter=%d tos=%d %s\n", pktSize, pIcmpHdrRcv->sn, pIpHdrRcv->ttl,\
                       diffTime, abs(jitter), pIpHdrRcv->tos, getTos(pIpHdrRcv->tos));

                timeSum += diffTime;
                sucessRcvPkt++;
                Sleep(interval);
                break;
            }

            //For some icmp errors
            if(pIcmpHdrRcv->type == 3 || \
                    pIcmpHdrRcv->type == 11 || \
                    pIcmpHdrRcv->type == 12 || \
                    pIcmpHdrRcv->type == 4 || \
                    pIcmpHdrRcv->type == 5)
            {

                type = pIcmpHdrRcv->type; code = pIcmpHdrRcv->code;
                addr.S_un.S_addr = *((u_long*) &(pIpHdrRcv->saddr));
                rcvAddr = inet_ntoa(addr);

                //Go to inside header
                pIpHdrRcv = (ip_header *) (pPktRcv + sizeof(eth_header) + sizeof(ip_header) + sizeof(icmp_header));
                pIcmpHdrRcv = (icmp_header *) (pPktRcv + sizeof(eth_header) + 2*sizeof(ip_header) + sizeof(icmp_header));
                if(pIpHdrRcv->identification == pIpHdrSnd->identification &&\
                        pIcmpHdrRcv->sid == pIcmpHdrSnd->sid &&\
                        pIcmpHdrRcv->sn == pIcmpHdrSnd->sn)
                {
                    printf("%s: ",rcvAddr);
                    type_code_decoder(type, code);
                    faultRcvPkt++;
                    break;
                }
            }
        }
        pIpHdrSnd->identification += 1;
        pIcmpHdrSnd->sn += 1;

        /*Checksum re-calculate*/
        pIpHdrSnd->crc = pIcmpHdrSnd->crc = 0;
        pIpHdrSnd->crc = cksum((u_short *)pIpHdrSnd,sizeof(ip_header));
        pIcmpHdrSnd->crc = cksum((u_short *)pIcmpHdrSnd,pktSize-(sizeof(eth_header) + sizeof(ip_header)));
        pktCount -= loop;
    }
    /*End loop*/

    printStat();
    pcap_close(fsend);
    pcap_close(frecv);

	return 0;
}


int str_to_int(char *str)
{
    int ret=0;
    while(*str != 0)
    {        
        if(*str < '0' || *str > '9')
            return 0;
        ret = ret*10 + (*str - 48); // 48 equal to zero in ascii code
        str++;
    }
    return ret;
}

int argv_parser(char *str)
{
    if(strcmp(str,"-t\0") == 0)
        return INFINITE_PING_FLAG;
    if(strcmp(str,"-f\0") == 0)
        return DF_FLAG;
    if(strcmp(str,"-n\0") == 0)
        return ARGV_N;
    if(strcmp(str,"-l\0") == 0)
        return ARGV_L;
    if(strcmp(str,"-v\0") == 0)
        return ARGV_TOS;
    if(strcmp(str,"-h\0") == 0)
        return ARGV_TTL;
    if(strcmp(str,"--sid\0") == 0)
        return ARGV_SID;
    if(strcmp(str,"--sn\0") == 0)
        return ARGV_SN;
    if(strcmp(str,"-w\0") == 0)
        return ARGV_W;
    if(strcmp(str,"-i\0") == 0)
        return ARGV_IVAL;
    if(strcmp(str,"--help\0") == 0)
        return ARGV_HELP;

    return 0;
}

void error_exit(char *error)
{
    printf("%s",error);
    exit(-1);
}

int CtrlHandler(DWORD fdwCtrlType)
{
    switch(fdwCtrlType)
    {
    case CTRL_C_EVENT:
        printStat();
        return 0;
    case CTRL_BREAK_EVENT:
        printStat();
        return 1;
    default:
          return FALSE;
    }

}

u_short cksum(u_short *field, int len)
{
  long sum = 0;  /* assume 32 bit long, 16 bit short */
  u_short *tmp;

  tmp = (u_short *) field;

  while(len > 1){
    sum += *tmp;
    tmp++;


    if(sum & 0x80000000)   /*if high order bit set, fold*/
      sum = (sum & 0xFFFF) + (sum >> 16);

    len -= 2;
  }

  if(len)       /* take care of left over byte */
    sum += *(unsigned char *)tmp;

  while(sum>>16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

void usage(char *name)
{
    printf("usage: %s [-t] [-f] [-n num] [-l len] [-v TOS]\n\t\t [-i interval] [-h TTL] [--sid sid] [--sn sn] [-w timeout] host\n\n",name);
    printf("Options:\n");
    printf("\t-t\t\tInfinite ping\n");
    printf("\t-f\t\tDF Bit\n");
    printf("\t-n num\t\tPackets count (default is 4)\n");
    printf("\t-l len\t\tSize of the packet. 64 < [size] < 1500 (default is 100)\n");
    printf("\t-v TOS\t\tTOS\n");
    printf("\t-i int\t\tInterval(in ms) between recieve packet and send the next one\n\t\t\t\t\t\t\t\t(Default is 1000ms)\n");
    printf("\t-h TTL\t\tTime to live\n");
    printf("\t--sid SID\t\tSID field of ICMP header (radnom by default)\n");
    printf("\t--sn SN\t\t\tstart SN field of ICMP header (1 by default)\n");
    printf("\t-w timeout\t\tTimeout in seconds. (Default is 4)\n");
}

void printStat()
{
    float s = sucessRcvPkt, f = faultRcvPkt;
    if(sucessRcvPkt)
        printf("\nSuccess: %.2f%% (%d/%d)  avg rtt: %dms  avg jitter: %d\n Min rtt: %dms Max rtt: %dms\n",(s/(s+f))*100,\
               sucessRcvPkt, sucessRcvPkt+faultRcvPkt, timeSum/sucessRcvPkt, jitterSum/sucessRcvPkt, minTime, maxTime);
    else
        printf("\nSuccess: 0%%\n");

}

void type_code_decoder(int type, int code)
{
    switch(type)
    {
        case 3:
            switch(code)
            {
                case 1:
                    printf("Host Unreachable\n");
                    break;
                case 2:
                    printf("Protocol Unreachable\n");
                    break;
                case 3:
                    printf("Port Unreachable\n");
                    break;
                case 4:
                    printf("Fragmentation Needed and Don't Fragment was Set\n");
                    break;
                default:
                    printf("Destination unreacheble\n");
                    break;
            }
            break;
        case 11:
            switch(code)
            {
                case 0:
                    printf("Time to live exceeded in transit\n");
                    break;
                case 1:
                    printf("Fragment reassembly time exceeded\n");
                    break;
                default:
                    printf("Time Exceeded Message\n");
                    break;
            }
            break;
        case 12:
            printf("Parameter Problem Message\n");
            break;

        case 4:
            printf("Source Quench Message\n");
            break;

        case 5:
            switch(code)
            {
                case 0:
                    printf("Redirect datagrams for the Network\n");
                    break;
                case 1:
                    printf("Redirect datagrams for the Host\n");
                    break;
                case 2:
                    printf("Redirect datagrams for the Type of Service and Network\n");
                    break;
                case 3:
                    printf("Redirect datagrams for the Type of Service and Host\n");
                    break;
                default:
                    printf("Redirect Message\n");
                    break;
            }
            break;

        default:
            printf("Unknown error. type=%d code=%d\n",type,code);
    }

    return;
}

char *getTos(int tos)
{
    switch(tos)
    {
        case 32:
            strcpy(tosStr, " cs1");
            break;
        case 40:
            strcpy(tosStr, " af11");
            break;
        case 48:
            strcpy(tosStr, " af12");
            break;
        case 56:
            strcpy(tosStr, " af13");
            break;
        case 64:
            strcpy(tosStr, " cs2");
            break;
        case 72:
            strcpy(tosStr, " af21");
            break;
        case 80:
            strcpy(tosStr, " af22");
            break;
        case 88:
            strcpy(tosStr, " af23");
            break;
        case 96:
            strcpy(tosStr, " cs3");
            break;
        case 104:
            strcpy(tosStr, " af31");
            break;
        case 112:
            strcpy(tosStr, " af32");
            break;
        case 120:
            strcpy(tosStr, " af33");
            break;
        case 128:
            strcpy(tosStr, " cs4");
            break;
        case 136:
            strcpy(tosStr, " af41");
            break;
        case 144:
            strcpy(tosStr, " af42");
            break;
        case 152:
            strcpy(tosStr, " af43");
            break;
        case 160:
            strcpy(tosStr, " cs5");
            break;
        case 184:
            strcpy(tosStr, " ef");
            break;
        case 192:
            strcpy(tosStr, " cs6");
            break;
        case 224:
            strcpy(tosStr, " cs7");
            break;
        default:
            strcpy(tosStr, " ");
            break;

    }
    return tosStr;
}

void minmaxTime(int tm)
{
    if(minTime == -1 || tm < minTime)
        minTime = tm;
    if(tm > maxTime)
        maxTime = tm;


}
