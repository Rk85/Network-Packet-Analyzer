import socket
from struct import unpack
import pcapy

class EthHeader(object):
    '''
        Description : class to store the details of ethernet link protocol/layer
        
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
           Description : Initialize the ethernet header details
           
        '''
        self.hdr_length = 14
        self.header_start = 0
        self.device = device 
        self.dest_mac = None
        self.src_mac = None
        self.proto = 0
        # For virtual interfaces,extra two bytes added to ethernet header
        if pcapy.DLT_LINUX_SLL == device.datalink():
            self.hdr_length = 16
            self.header_start = 2
    
    def eth_addr (self, a):
        '''
            Description : Return the ethernet header MAC address 
                          in proper format
            
            input_param : a - string contains the MAC address
            input_type : string 
            
            out_param : b - MAC address in proper format
            out_type : string
            
        '''
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b
    
    def get_details(self, packet):
        '''
           Description : Assigns values to the ethernet header class 
                         attributes from the details present 
                         in the given packet
           
           input_param : packet - packet received in the interface
           input_type : bytes array
           
        '''
        eth_header = packet[self.header_start:self.hdr_length]
        eth = unpack('!6s6sH' , eth_header)
        
        self.proto = socket.ntohs(eth[2])
        self.dest_mac = self.eth_addr(packet[0:6])
        self.src_mac = self.eth_addr(packet[6:12])
