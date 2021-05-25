#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h> //ethernet header
#include <netinet/ip.h>   //ip header
#include <netinet/tcp.h>  //tcp header
#include <arpa/inet.h>    //inet_ntoa()

struct ether_header *ethh;
struct ip *iph;
struct tcphdr *tcph;
struct udphdr *udph;

struct Virtual_LAN
{
    uint16_t id;
    uint16_t type;
}*virtual_lanh;

#pragma pack(push,1) // cause padding -> real size is 11
struct goose_header
{
    uint16_t appid;
    uint16_t length;
    uint16_t reserved1;
    uint16_t reserved2;
    uint16_t goosePdu_tag; //hmm.. maybe 2byte..? right?
    uint8_t goosePdu_len;
}*gooseh;
#pragma pack(pop)

struct goose_pdu
{
    uint8_t tag_gocbRef;
    uint8_t len_gocbRef;
    uint8_t *gocbRef;

    uint8_t tag_dataSet;
    uint8_t len_dataSet;
    uint8_t *dataSet;

    uint8_t tag_goID;
    uint8_t len_goID;
    uint8_t goID;

    uint8_t tag_time;
    uint8_t len_time;
    uint8_t *time;

    uint8_t tag_stNum;
    uint8_t len_stNum;
    uint8_t *stNum;

    uint8_t tag_sqNum;
    uint8_t len_sqNum;
    uint8_t *sqNum;

    uint8_t tag_test;
    uint8_t len_test;
    uint8_t test;

    uint8_t tag_confRev;
    uint8_t len_confRev;
    uint8_t *confRev;

    uint8_t tag_ndsCom;
    uint8_t len_ndsCom;
    uint8_t *ndsCom;

    uint8_t tag_numDataSetEntries;
    uint8_t len_numDataSetEntries;
    uint8_t *numDataSetEntries;

    uint8_t tag_allData;
    uint8_t len_allData;
    uint8_t *allData;
}*goose_pduh;


void goose_dump(const u_char* packet);
void virtual_lan_dump(const u_char* packet);
void ethernet_dump(const u_char* packet);
void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet);
void usage()
{
  printf("sysntax : goose_parser <interface>\n");
  printf("sample@linux~$ ./goose_parser ens33\n");
}



int main(int argc, char* argv[])
{
  // usage error check!
  if(argc != 2)
  {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];  // errbuf
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);  // packet descripter

  dev = pcap_lookupdev(errbuf);

  // device error check!
  if(handle == NULL)
  {
    fprintf(stderr,"Couldn't open device : %s : %s\n",dev,errbuf);
    return -1;
  }
  printf("Device : %s\n",dev);

  pcap_loop(handle,0,callback,NULL);
  return 0;
}
void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet)
{
    // Ethernet header
    ethh = (struct ether_header *)packet;
    ethernet_dump(packet);
    packet += sizeof(struct ether_header);

    // GOOSE Header Paring(on IEC 61850)
    if(ntohs(ethh->ether_type) == 0x88b8)
    {
        goose_dump(packet);
    }

    if(ntohs(ethh->ether_type) == 0x8100)
    {
        virtual_lan_dump(packet);
        packet += sizeof(struct Virtual_LAN);
        goose_dump(packet);
    }
}

void ethernet_dump(const u_char* packet)
{
//    ethh = (struct ether_header *)packet;
    printf("\n[Layer 2] DataLink\n");
    printf("[*]Dst Mac address[*] : ");

    for(int i = 0; i < 6; i++)
    {
       printf("%02x", packet[i]);
       if (i != 5)
        printf(":");
    }
    printf("\n");
    printf("[*]Src Mac address[*] : ");
    for(int i = 6; i < 12; i++)
    {
       printf("%02x", packet[i]);
       if (i != 11)
        printf(":");
    }
    printf("\n");

    printf("type : %#x\n", ntohs(ethh->ether_type));
}

void virtual_lan_dump(const u_char* packet)
{
    virtual_lanh = (struct Virtual_LAN *)packet;
    printf("\n[Layer 3] High-Level Link\n");
    printf("[*]ID[*] : %d\n", ntohs(virtual_lanh->id));
    printf("[*]Type[*] : %#x\n", ntohs(virtual_lanh->type));
}

void goose_dump(const u_char* packet)
{
    gooseh = (struct goose_header *)packet;
    printf("[*]appid[*] : %#x\n", ntohs(gooseh->appid));
    printf("[*]Length[*] : %d\n", ntohs(gooseh->length));
    printf("[*]Reserved[*] 1 : %#x\n", ntohs(gooseh->reserved1));
    printf("[*]Reserved[*] 2 : %#x\n", ntohs(gooseh->reserved2));
    printf("[*]goosePduTAG[*] : %#x\n", ntohs(gooseh->goosePdu_tag));
    printf("[*]goosePduLENGTH[*] : %#x\n", gooseh->goosePdu_len);

    //goosePdu dump
    packet += sizeof(struct goose_header);
    uint8_t tag_gocbRef = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_gocbRef = *packet;
    uint8_t gocbRef[len_gocbRef];
    packet += sizeof(uint8_t);
    memcpy(gocbRef, packet, len_gocbRef);

//    printf("    tag_gocRef : %#x\n", tag_gocbRef);
//    printf("    len_gocRef : %#x\n", len_gocbRef);
    printf("gocRef : %s\n", gocbRef);

    packet += len_gocbRef;
    uint8_t tag_timeAllowedtoLive = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_timeAllowedtoLive = *packet;
    packet += sizeof(uint8_t);
    uint8_t timeAllowedtoLive[len_timeAllowedtoLive];
    packet += sizeof(uint16_t);
    memcpy(timeAllowedtoLive, packet, len_timeAllowedtoLive);

//    printf("    tag_timeAllowedtoLive : %#x\n", tag_timeAllowedtoLive);
//    printf("    len_timeAllowedtoLive : %#x\n", len_timeAllowedtoLive);
    printf("timeAllowedtoLive : %#x\n", ntohs(*timeAllowedtoLive));


    packet += (len_timeAllowedtoLive - sizeof(uint16_t));
    uint8_t tag_dataSet = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_dataSet = *packet;
    packet += sizeof(uint8_t);
    uint8_t dataSet[len_dataSet];
    memcpy(dataSet, packet, len_dataSet);

//    printf("    tag_dataSet : %#x\n", tag_dataSet);
//    printf("    len_dataSet : %#x\n", len_dataSet);
    printf("dataSet : %s\n", dataSet);

    packet += len_dataSet;
    uint8_t tag_goID = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_goID = *packet;
    packet += sizeof(uint8_t);
    uint8_t goID[len_goID];
    memcpy(goID, packet, len_goID);

//    printf("    tag_goID : %#x\n", tag_goID);
//    printf("    len_goID : %#x\n", len_goID);
    printf("goID : %s\n", goID);

    packet += len_goID;
    uint8_t tag_time = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_time = *packet;
    packet += sizeof(uint8_t);
    uint8_t time[len_time];
    memcpy(time, packet, len_time);

//    printf("    tag_time : %#x\n", tag_time);
//    printf("    len_time : %#x\n", len_time);
    printf("time : %s\n", time);

    packet += len_time;
    uint8_t tag_stNum = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_stNum = *packet;
    packet += sizeof(uint8_t);
    uint8_t stNum = *packet;

//    printf("    tag_stNum : %#x\n", tag_stNum);
//    printf("    len_stNum : %#x\n", len_stNum);
    printf("stNum : %d\n", stNum);

    packet += len_stNum;
    uint8_t tag_sqNum = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_sqNum = *packet;
    packet += sizeof(uint8_t);
    uint8_t sqNum = *packet;

//    printf("    tag_sqNum : %#x\n", tag_sqNum);
//    printf("    len_sqNum : %#x\n", len_sqNum);
    printf("sqNum : %d\n", sqNum);

    packet += len_sqNum;
    uint8_t tag_test = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_test = *packet;
    packet += sizeof(uint8_t);
    uint8_t test = *packet;

//    printf("    tag_test : %#x\n", tag_test);
//    printf("    len_test : %#x\n", len_test);
    if(test == 0x00)
        printf("test : False\n");
    else if(test == 0x01)
        printf("test : True\n");


    packet += len_test;
    uint8_t tag_confRev = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_confRev = *packet;
    packet += sizeof(uint8_t);
    uint8_t confRev = *packet;

//    printf("    tag_confRev : %#x\n", tag_confRev);
//    printf("    len_confRev : %#x\n", len_confRev);
    printf("confRev : %d\n", confRev);

    packet += len_test;
    uint8_t tag_ndsCom = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_ndsCom = *packet;
    packet += sizeof(uint8_t);
    uint8_t ndsCom = *packet;

//    printf("    tag_ndsCom : %#x\n", tag_ndsCom);
//    printf("    len_ndsCom : %#x\n", len_ndsCom);
    if(ndsCom == 0x00)
        printf("ndsCom : False\n");
    else if(ndsCom == 0x01)
        printf("ndsCom : True\n");


    packet += len_ndsCom;
    uint8_t tag_numDataSetEntries = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_numDataSetEntries = *packet;
    packet += sizeof(uint8_t);
    uint8_t numDataSetEntries = *packet;

//    printf("    tag_numDataSetEntries : %#x\n", tag_numDataSetEntries);
//    printf("    len_numDataSetEntries : %#x\n", len_numDataSetEntries);
    printf("numDataSetEntries : %d\n", numDataSetEntries);

    packet += len_numDataSetEntries;
    uint8_t tag_allData = *packet;
    packet += sizeof(uint8_t);
    uint8_t len_allData = *packet;
    packet += sizeof(uint8_t);

//    printf("    tag_allData : %#x\n", tag_allData);
//    printf("    len_allData : %#x\n", len_allData);
}
