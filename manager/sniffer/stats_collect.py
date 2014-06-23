import socket
import signal
import fcntl
import struct
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
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

packet_stats = {
                "total_packets": 0,
                "total_recv_packets": 0,
                "total_sent_packets": 0,
                "total_data": 0,
                "total_recv_data": 0,
                "total_sent_data": 0
}

def get_ip_address_list():
    '''
        Description : Gets the IP address of the available interfaces
        
        out_param : ip_address_list - list of available interface IPs
        out_type : list
        
        sample_output : [ '127.0.0.1', '192.168.2.1' ]
        
    '''
    ip_address_list = []
    for device in pcapy.findalldevs():
        if device != 'any':
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip_address_list.append(
                socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR  
                    struct.pack('256s', device[:15])
                    )[20:24]
                )
            )
    return ip_address_list

SOURCE_IP_ADDRESS = get_ip_address_list()

def parse_packet(header, packet) :
    '''
        Description : Parses the given packets and writes its information
                      into a file as string
        
        input_param : header - information describing the data passed
                       and the data itself
        input_type : Pkthdr instance
        
        input_param : packet - sniffed packet
        input_type : bytes array
        
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
            logger.debug("TCP packet")
            tcp_hdr = TcpHeader(settings.packet_reader)
            tcp_hdr.get_details(packet[t:t+tcp_hdr.DEFAULT_LENGTH])
            tot_hdr_size = t + tcp_hdr.hdr_length 
        
        # ICMP Packets    
        elif ip_hdr.proto == ICMP_PROTOCOL_ID :
            logger.debug("ICMP packet")
            icmp_hdr = IcmpHeader(settings.packet_reader)
            icmp_hdr.get_details(packet[t:t+icmp_hdr.DEFAULT_LENGTH])
            tot_hdr_size = t + icmp_hdr.hdr_length
            
        # UDP packets
        elif ip_hdr.proto == UDP_PROTOCOL_ID :
            logger.debug("UDP packet")
            udp_hdr = UdpHeader(settings.packet_reader)
            udp_hdr.get_details(packet[t:t+udp_hdr.DEFAULT_LENGTH])
            tot_hdr_size = t + udp_hdr.hdr_length
 
        # some other IP packet like IGMP
        else :
            logger.debug("Protocol other than TCP/UDP/ICMP")
        
    if tot_hdr_size:     
        data_size = len(packet) - tot_hdr_size
        logger.debug('Data : {0}'.format(packet[tot_hdr_size:]))
        packet_stats['total_packets'] = packet_stats['total_packets'] + 1
        packet_stats['total_data'] = packet_stats['total_data'] + data_size
        if ip_hdr.src_addr in SOURCE_IP_ADDRESS:
            packet_stats["total_sent_packets"] = packet_stats["total_sent_packets"] + 1
            packet_stats["total_sent_data"] = packet_stats["total_sent_data"] + data_size
        else:
            packet_stats["total_recv_packets"] = packet_stats["total_recv_packets"] + 1
            packet_stats["total_recv_data"] = packet_stats["total_recv_data"] + data_size
def main(argv):
    '''
        Description : Main function to read packet from the dumped file
        
        input_param : argv - command line arguement list
        input_type : list
        
    '''
    settings.packet_reader = pcapy.open_offline(settings.dump_file)
    settings.packet_reader.setnonblock(True)
    #filters = ' '.join(argv[1:] ) if len(argv) > 1 else ''
    filters = ''
    try:
       settings.packet_reader.setfilter(filters)
    except pcapy.PcapError:
        logger.error("Syntax error in options : {0}".format(filters))
        logger.info("For Options syntax, Please refer the link http://biot.com/capstats/bpf.html")
        sys.exit(-1)
 
    # start sniffing packets
    while(1) :
        packets_read = settings.packet_reader.dispatch(1, parse_packet)
        if not packets_read:
            with open(settings.stats_file, "w") as stats_file:
                stats_file.write(str(packet_stats))
            break

def sigint_handler(signum, frame):
    '''
        Description : Signal handler function to grace fully exit
        
        input_param : signum - generated signal number 
        input_type : INT
        
        input_param : frame - Stack frame of the generated signal
        input_type : frame class object
        
        out_param :
        out_type :
        
        sample_output :
    '''

    logger.debug('Stop pressing the CTRL+C!')
    with open(settings.stats_file, "w") as stats_file:
        stats_file.write(str(packet_stats))
    sys.exit(0)

# Register Signal handler
signal.signal(signal.SIGINT, sigint_handler)
if __name__ == "__main__":
    main(sys.argv)
