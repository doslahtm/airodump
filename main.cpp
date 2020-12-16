#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include "airodump.h"
#include <iostream>

#define DOT11BUFSIZE 11000

pcap_t* handle;


void usage()
{
    puts("syntax : airodump <interface>");
    puts("sample : airodump mon0");
    return ;
}

void setup()
{
    setvbuf(stdin , 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
    return ;
}

void SigIntHandler(int sig)
{
    printf("Quitting....\n");
    pcap_close(handle);
    exit(0);
}

int main(int argc, char *argv[])
{
    setup();

    if (argc != 2)
    {
        usage();
        return -1;
    }
    
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, DOT11BUFSIZE, 1, 1, errbuf);
    if ( handle == nullptr )
    {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s", dev, errbuf);
        return -1;
    }
    
    // set when received sigint, terminate program 
    struct sigaction ExitProcess;
    ExitProcess.sa_handler = SigIntHandler;
    sigemptyset(&ExitProcess.sa_mask);
    ExitProcess.sa_flags = 0;
    if ( sigaction(SIGINT, &ExitProcess, 0) == -1 )
    {
        printf("signal(SIGINT) error\n");
        return -1;
    }


    while ( true )
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        map<Mac, BeaconInfo>::iterator it;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        AnalyzePkt((char*)packet);
        
    }
    
    return 0;
}