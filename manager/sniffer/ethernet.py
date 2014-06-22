import socket
from struct import unpack
import pcapy

class EthHeader(object):
    '''
        Returns all the details about the data link protocol details/layer
        sample packet structure
        
          0                6            12         14                         1514     1518
       -------------------------------------------------------------------------------------
       |  Destination Mac  | Source Mac | Eth Type | Pay Load ( 46-1500 Bytes) | checksum  |
       -------------------------------------------------------------------------------------
       
       Eth Type : if <1500 it means Header length else represents below types
                  0X0800 - IP
                  0X0806 - ARP
        
    '''
    def __init__(self, device):
        '''
           Initialize the header details
        '''
        self.hdr_length = 14
        self.header_start = 0
        self.device = device 
        self.dest_mac = None
        self.src_mac = None
        self.proto = 0
        if pcapy.DLT_LINUX_SLL == device.datalink():
            self.hdr_length = 16
            self.header_start = 2
    
    def eth_addr (self, a):
        '''
            Return the ethernet header in proper format
        '''
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b
    
    def get_details(self, packet):
        '''
           Returns the ethernet header details present 
           in the given packet
        '''
        eth_header = packet[self.header_start:self.hdr_length]
        eth = unpack('!6s6sH' , eth_header)
        
        self.proto = socket.ntohs(eth[2])
        self.dest_mac = self.eth_addr(packet[0:6])
        self.src_mac = self.eth_addr(packet[6:12])
