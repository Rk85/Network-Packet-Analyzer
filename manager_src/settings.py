# This variable should never be imported 
# directly in any module always use as settings.packet_reader
packet_reader = ''
dump_file = "rk.txt"
dump_file_writer = ''

# Protocol Ids 
IP_PROTOCOL_ID = 8
TCP_PROTOCOL_ID = 6
ICMP_PROTOCOL_ID = 1
UDP_PROTOCOL_ID = 17

upload_sniffer_files = [ 'icmp.py',
    'stats_collect.py',
    'sniff_packet.py',
    'udp.py',
    'ethernet.py',
    'ip.py',
    'tcp.py',
    'settings.py'
]

sniffer_file = 'sniff_packet.py'
stats_collect_file = 'stats_collect.py'
