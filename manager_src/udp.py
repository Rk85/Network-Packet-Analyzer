from struct import unpack

class UdpHeader(object):
    '''
        Returns all the details about the UDP protocol details/layer
        sample packet structure
        
         0      7 8     15 16    23 24    31  
         +--------+--------+--------+--------+ 
         |     Source      |   Destination   | 
         |      Port       |      Port       | 
         +--------+--------+--------+--------+ 
         |                 |                 | 
         |     Length      |    Checksum     | 
         +--------+--------+--------+--------+ 
        
    '''
    
    DEFAULT_LENGTH = 8
    
    def __init__(self, device):
        '''
           Initialize the header details
        '''
        self.device = device
        self.src_port = 0
        self.dst_port = 0
        self.hdr_length = 0
        self.checksum = 0 
    
    def get_details(self, packet):
        '''
          Returns the UDP Layer header details present 
          in the given packet
        '''
        udph = unpack('!HHHH' , packet)
         
        self.src_port = udph[0]
        self.dst_port = udph[1]
        self.hdr_length = udph[2]
        self.checksum = udph[3]
