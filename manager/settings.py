# This variable should never be imported 
# directly in any module always use as settings.DESIGN_DATA

import logging

# DB Related Configurations
COUCH_DB_IP = "127.0.0.1"
COUCH_DB_PORT = "5984"
DB_NAME = "packet_analyzer"
DB_DESIGN_FILE = "templates/db_design.json"
#REWRITE_DESIGN = True
REWRITE_DESIGN = False
BASE_URL = "http://" + COUCH_DB_IP + ":" + str(COUCH_DB_PORT) + "/" + DB_NAME
DESIGN_DATA = ''
with open(DB_DESIGN_FILE, "r") as fd:
    DESIGN_DATA =  "".join( fd.readlines() )

# Required Files list that should be uploaded to client 
# to start the packet sniffer
upload_sniffer_files = [ 'icmp.py',
    'stats_collect.py',
    'sniff_packet.py',
    'udp.py',
    'ethernet.py',
    'ip.py',
    'tcp.py',
    'settings.py'
]

SNIFFER_FOLDER = "sniffer"
sniffer_file = 'sniff_packet.py'
stats_collect_file = 'stats_collect.py'
client_port = 8081

# logging configurations
DEBUG_FORMAT = "%(levelname)s at %(asctime)s in function '%(funcName)s' in file \"%(pathname)s\" at line %(lineno)d: %(message)s"

LOG_CONFIG = {
              'version': 1,
              'formatters': {'debug': {'format': DEBUG_FORMAT}},
              'handlers': {
                            'console': {
                                         'class': 'logging.StreamHandler',
                                         'formatter': 'debug',
                                         'level': logging.DEBUG
                                       }
                         },
              'root': {
                       'handlers':['console'], 'level': 'DEBUG'
                      }
             }
