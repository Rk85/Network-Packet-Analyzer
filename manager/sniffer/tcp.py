from struct import unpack


class TcpHeader(object):
    '''
         Description : class to store the details of TCP protocol/layer
        
        sample packet structure
         0                            15                              31
       -----------------------------------------------------------------
       |          source port          |       destination port        |
       -----------------------------------------------------------------
       |                        sequence number                        |
       -----------------------------------------------------------------
       |                     acknowledgment number                     |
       -----------------------------------------------------------------
       |  HL   | rsvd  |C|E|U|A|P|R|S|F|        window size            |
       -----------------------------------------------------------------
       |         TCP checksum          |       urgent pointer          |
       -----------------------------------------------------------------
        
    '''
    
    DEFAULT_LENGTH = 20
    
    def __init__(self, device):
        '''
           Description : Initialize the TCP header details
           
        '''
        self.device = device
        self.src_port = 0
        self.dst_port = 0
        self.sequence = 0
        self.acknowledgement = 0
        self.hdr_length = 0
        self.tcp_bits = {}
        self.window_size = 0
        self.checksum = 0
        self.urg_pointer = 0

    def get_tcp_bits(self, bit_val):
        '''
            Returns the tcp Control bits in dictionary
        '''
        return {
                'tcp_FIN' : bit_val & 1,
                'tcp_SYN' : bit_val & 2,
                'tcp_RST' : bit_val & 4,
                'tcp_PUSH': bit_val & 8,
                'tcp_ACK' : bit_val & 16,
                'tcp_URG' : bit_val & 32
            }

    def get_details(self, packet):
        '''
           Description : Assigns values to the TCP header class 
                         attributes from the details present 
                         in the given packet
           
           input_param : packet - packet received in the interface
           input_type : bytes array
           
        '''
        tcph = unpack('!HHLLBBHHH' , packet)
        self.src_port = tcph[0]
        self.dst_port = tcph[1]
        self.sequence = tcph[2]
        self.acknowledgement = tcph[3]
        self.hdr_length = (tcph[4] >> 4 ) * 4
        self.tcp_bits = self.get_tcp_bits(tcph[5])
        self.window_size = tcph[6]
        self.checksum = tcph[7]
        self.urg_pointer = tcph[8]
