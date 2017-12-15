#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include<unistd.h>
#include<time.h>
#include<signal.h>
#include<string.h>

int count = 1;
int total_count=0;
int threshold=5;
int clientSocket;
int linktype;
int linkhdrlen;
struct sockaddr_in serverAddr;
char buffer[1024];
pcap_t* descr;
int buf[100][256];
int ind=0;

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
//printf("%d, ",count);
fprintf(stdout,"%d, ",count);
fflush(stdout);
count++;
	
}

void set_linktype(pcap_t* descr) {

switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
 
    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", linktype);
    }
}

void signal_handler() {
	total_count+=count;	
	if(count>threshold) {
		strcpy(buffer,"ON_AN_ATTACK\n");
  		send(clientSocket,buffer,14,0);	
		fprintf(stdout," Done\n");
		fflush(stdout);
		alarm(0);
		pcap_breakloop(descr);
	} else {
		fprintf(stdout, "in handler\n");
		fflush(stdout);
	}
	count=1;
	alarm(1);
 }


void signal_handler2() {
	send(clientSocket,buf,ind*256,0);
	ind=0;
}

/*void parse_function(u_char *user, struct pcap_pkthdr *packethdr, 
                  u_char *packetptr)
{
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
    unsigned short id, seq;
 
    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
 
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        buf[ind] =  ntohs(tcphdr->dest);
      	ind++;
        break;
 
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
               dstip, ntohs(udphdr->dest));
        break;
 
    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        break;
    }
    
}
*/

int main(int argc,char **argv){
  socklen_t addr_size;
  int i;
  char *dev; 
  char errbuf[PCAP_ERRBUF_SIZE];
  const u_char *packet;
  struct pcap_pkthdr hdr;     /* pcap.h */
  struct ether_header *eptr;  /* net/ethernet.h */

   signal(SIGALRM,signal_handler);

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  clientSocket = socket(PF_INET, SOCK_STREAM, 0);
  
  /*---- Configure settings of the server address struct ----*/
  /* Address family = Internet */
  serverAddr.sin_family = AF_INET;
  /* Set port number, using htons function to use proper byte order */
  serverAddr.sin_port = htons(7891);
  /* Set IP address to localhost */
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  /* Set all bits of the padding field to 0 */
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero); 

   /*---- Connect the socket to the server using the address struct ----*/
  addr_size = sizeof serverAddr;
  connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size); 


    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { 
	printf("%s\n",errbuf); exit(1); 
    }

    /* open device for reading */
    descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    if(descr == NULL) { 
	printf("pcap_open_live(): %s\n",errbuf); 
	exit(1); 
	}

   set_linktype(descr);
   alarm(1);
    
    pcap_loop(descr,-1,my_callback,NULL);
	
    signal(SIGALRM,signal_handler2);

    recv(clientSocket, buffer, 1024, 0);
	printf("%s\n",buffer);
	//alarm(1);
       /*if(strcmp(buffer,"START ")) {	
           pcap_loop(descr,-1,(pcap_handler)parse_function,NULL);
       }*/

  return 0;
}


