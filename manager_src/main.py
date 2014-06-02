import socket
import signal
from struct import unpack
import datetime
import pcapy
import sys
from optparse import OptionParser
from ethernet import EthHeader
from ip import IPHeader
from tcp import TcpHeader
from icmp import IcmpHeader
from udp import UdpHeader
import settings
from settings import (
    IP_PROTOCOL_ID,
    TCP_PROTOCOL_ID,
    ICMP_PROTOCOL_ID,
    UDP_PROTOCOL_ID 
)


def parse_packet(header, packet) :
    '''
        Parse the network packet and retrieves the relavant informations
        from the pacjet
    '''
    eth_hdr = EthHeader(settings.packet_reader)
    eth_hdr.get_details(packet)    
    tot_hdr_size = 0 
    
    if eth_hdr.proto == IP_PROTOCOL_ID :
        # Parse IP header
        # take first 20 characters for the ip header
        ip_hdr = IPHeader(settings.packet_reader)
        ip_hdr.get_details(packet[eth_hdr.hdr_length:ip_hdr.DEFAULT_LENGTH+eth_hdr.hdr_length])
        t = ip_hdr.hdr_length + eth_hdr.hdr_length
 
        # TCP protocol
        if ip_hdr.proto == TCP_PROTOCOL_ID :
            # print "TCP"
            tcp_hdr = TcpHeader(settings.packet_reader)
            tcp_hdr.get_details(packet[t:t+tcp_hdr.DEFAULT_LENGTH])
            tot_hdr_size = t + tcp_hdr.hdr_length 
        
        # ICMP Packets    
        elif ip_hdr.proto == ICMP_PROTOCOL_ID :
            # print "ICMP"
            icmp_hdr = IcmpHeader(settings.packet_reader)
            icmp_hdr.get_details(packet[t:t+icmp_hdr.DEFAULT_LENGTH])
            tot_hdr_size = t + icmp_hdr.hdr_length
            
        # UDP packets
        elif ip_hdr.proto == UDP_PROTOCOL_ID :
            # print "UDP"
            udp_hdr = UdpHeader(settings.packet_reader)
            udp_hdr.get_details(packet[t:t+udp_hdr.DEFAULT_LENGTH])
            tot_hdr_size = t + udp_hdr.hdr_length
 
        # some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP/ICMP'
        
    if tot_hdr_size:     
        data_size = len(packet) - tot_hdr_size
        print 'Data : ' + packet[tot_hdr_size:]
 
def main(argv):
    '''
        Main function to read packet from the dumped file
    '''
    settings.packet_reader = pcapy.open_offline("rk.txt")
    settings.packet_reader.setnonblock(True)
    filters = ' '.join(argv[1:] ) if len(argv) > 1 else ''
    try:
       settings.packet_reader.setfilter(filters)
    except pcapy.PcapError:
        print "Syntax error in options : " + filters
        print "For Options syntax, Please refer the link http://biot.com/capstats/bpf.html"
        sys.exit(-1)
 
    # start sniffing packets
    while(1) :
        settings.packet_reader.dispatch(1, parse_packet)

def sigint_handler(signum, frame):
    '''
        Signal handler function to grace fully exit
    '''
    print 'Stop pressing the CTRL+C!'
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint_handler)
    main(sys.argv)
