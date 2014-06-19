import socket
import signal
from struct import unpack
import datetime
import pcapy
import sys
import settings

def get_selected_device():
    '''
        Lists all the available ethernet interfaces 
        and returns the selected interface for sniffing the packets
        
    '''
    #list all devices
    devices = pcapy.findalldevs()
    print devices
     
    #ask user to enter device name to sniff
    print "Available devices are :"
    for d in devices :
        print d
     
    dev = raw_input("Enter device name to sniff : ")
     
    print "Sniffing device " + dev
    return dev
    
#function to parse a packet
def dump_packet(header, packet):
    '''
       Dump the packets into the file
    '''
    settings.dump_file_writer.dump(header, packet)
 
def main(argv, selected_device):
    # selected_device = get_selected_device() 
    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    settings.packet_reader = pcapy.open_live(selected_device , 65536 , 1 , 0)
    settings.dump_file_writer = settings.packet_reader.dump_open(settings.dump_file)
    settings.packet_reader.setnonblock(True)
    filters = ' '.join(argv) if argv else ''
    try:
       settings.packet_reader.setfilter(filters)
    except pcapy.PcapError:
        print "Syntax error in options : " + filters
        print "For Options syntax, Please refer the link http://biot.com/capstats/bpf.html"
        sys.exit(-1)
 
    #start sniffing packets
    while(1) :
        settings.packet_reader.dispatch(1, dump_packet)

def sigint_handler(signum, frame):
    '''
        Signal handler function to grace fully exit
    '''
    print 'Stop pressing the CTRL+C!'
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint_handler)
    if len(sys.argv) < 3 or sys.argv[1] != 'interface':
        print "Please Provide sniff interface as first arguement"
        sys.exit(0)
    filter_options = sys.argv[3:] if len(sys.argv) > 3 else []
    main(filter_options, sys.argv[2])
