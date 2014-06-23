import socket
import signal
from struct import unpack
import datetime
import pcapy
import sys
import settings
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
    
#function to parse a packet
def dump_packet(header, packet):
    '''
        Description : Dump the packets into the file in binary format
        
        input_param : header - information describing the data passed
                       and the data itself
        input_type : Pkthdr instance
        
        input_param : packet - sniffed packet
        input_type : bytes array
        
    '''
    settings.dump_file_writer.dump(header, packet)
 
def main(argv, selected_device):
    '''
        Description : main function of packet sniffer program
        
        input_param : argv - command line params
        input_type : list
        
        input_param : selected_device - selected interface name
        input_type : string
         
    '''
    settings.packet_reader = pcapy.open_live(selected_device , 65536 , 1 , 0)
    settings.dump_file_writer = settings.packet_reader.dump_open(settings.dump_file)
    settings.packet_reader.setnonblock(True)
    filters = ' '.join(argv) if argv else ''
    try:
       settings.packet_reader.setfilter(filters)
    except pcapy.PcapError:
        logger.error("Syntax error in options : {0}".format(filters))
        logger.info("For Options syntax, Please refer the link http://biot.com/capstats/bpf.html")
        sys.exit(-1)
 
    #start sniffing packets
    while(1) :
        settings.packet_reader.dispatch(1, dump_packet)

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
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)
if __name__ == "__main__":
    filter_options = sys.argv[1:]
    main(filter_options, 'any')
