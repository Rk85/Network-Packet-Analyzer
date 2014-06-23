from struct import unpack


class IcmpHeader(object):
    '''
        Description : class to store the details of ICMP protocol
        
        sample packet structure
        
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |     Code      |          Checksum             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             unused                            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      Internet Header + 64 bits of Original Data Datagram      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        
    '''
    
    DEFAULT_LENGTH = 4
    
    def __init__(self, device):
        '''
           Description : Initialize the ICMP header details
           
        '''
        self.device = device
        self.type = 0
        self.code = 0
        self.checksum = 0 
        self.hdr_length = 0
    
    def get_details(self, packet):
        '''
           Description : Assigns values to the ICMP header class 
                         attributes from the details present 
                         in the given packet
           
           input_param : packet - packet received in the interface
           input_type : bytes array
           
        '''
        
        icmph = unpack('!BBH' , packet)
        self.type = icmph[0]
        self.code = icmph[1]
        self.checksum = icmph[2]
        self.hdr_length = self.DEFAULT_LENGTH
         
