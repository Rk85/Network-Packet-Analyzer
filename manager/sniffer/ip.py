import socket
from struct import unpack

class IPHeader(object):
    '''
        Returns all the details about the IP protocol details/layer
        sample packet structure
        
        0                   1                   2                   3   
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  |Type of Service|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        
    '''
    
    DEFAULT_LENGTH = 20
    
    def __init__(self, device):
        '''
           Initialize the header details
        '''
        self.device = device
        self.version = 0
        self.hdr_length = 0
        self.ttl = 0
        self.proto = 0
        self.src_addr = ''
        self.dst_addr = ''
    
    def get_details(self, packet):
        '''
           Returns the IP Layer header details present 
           in the given packet
        '''

        iph = unpack('!BBHHHBBH4s4s' , packet)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
    
        iph_length = ihl * 4
    
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
     
        self.version = version
        self.hdr_length = iph_length
        self.ttl = ttl
        self.proto = protocol
        self.src_addr = s_addr
        self.dst_addr= d_addr
     
