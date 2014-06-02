from struct import unpack


class IcmpHeader(object):
    '''
        Returns all the details about the ICMP protocol details/layer
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
           Initialize the header details
        '''
        self.device = device
        self.type = 0
        self.code = 0
        self.checksum = 0 
        self.hdr_length = 0
    
    def get_details(self, packet):
        '''
           Returns the ICMP header details present 
           in the given packet
        '''
        icmph = unpack('!BBH' , packet)
        self.type = icmph[0]
        self.code = icmph[1]
        self.checksum = icmph[2]
        self.hdr_length = self.DEFAULT_LENGTH
         
