from struct import unpack

class UdpHeader(object):
    '''
        Description : class to store the details of UDP protocol/layer
       
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
           Description : Initialize the UDP header details
           
        '''
        self.device = device
        self.src_port = 0
        self.dst_port = 0
        self.hdr_length = 0
        self.checksum = 0 
    
    def get_details(self, packet):
        '''
           Description : Assigns values to the UDP header class 
                         attributes from the details present 
                         in the given packet
           
           input_param : packet - packet received in the interface
           input_type : bytes array
           
        '''
        
        udph = unpack('!HHHH' , packet)
         
        self.src_port = udph[0]
        self.dst_port = udph[1]
        self.hdr_length = udph[2]
        self.checksum = udph[3]
