import select, socket
import subprocess
import signal
import sys
import json
import logging
from logging import config

MAX_COUNT = 10

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

logging.config.dictConfig(LOG_CONFIG)
logger = logging.getLogger(__name__)

def creat_socket():
    '''
        Description : Creats new socket and returns it to make new connection
        
        input_param :
        input_type :
        
        out_param : new_socket - new socket to make new connection
        out_type : socket
        
        sampl_output :
    '''

    new_socket = 0
    try:
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception as e:
        logger.exception("Unable to create the socket : " + str(e))
        raise
    return new_socket

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

# Register the signal handler function
signal.signal(signal.SIGINT, sigint_handler)

if __name__ == "__main__":
    server_socket = creat_socket()
    server_socket.bind(('0.0.0.0', 8081))
    server_socket.listen(1)
    p = ''
    # Endless loop to receive commands from manager
    while True:
        connection, address = server_socket.accept()
        data = connection.recv(1024)
        logger.debug("Request data {0}".format(data))
        if data == "check_alive":
            connection.send("yes")
        elif data == "receive_packet_sniffer_file":
            start_count = 0
            connection.send("start")
            data = ""
            while start_count <= MAX_COUNT:
                data = data + connection.recv(1024)
                try:
                   json_data = json.loads(data)
                except ValueError:
                   logger.debug("Decode error while decoding json")
                   start_count = start_count + 1
                   json_data = None
                   continue
                break
            if json_data:
                with open(json_data['file_name'], 'w') as sniffer_file:
                    sniffer_file.write(json_data['file_content'])
            connection.send("end")
        elif data == "start_packet_sniffing":
            start_count = 0
            connection.send("start")
            data = ""
            while start_count <= MAX_COUNT:
                data = data + connection.recv(1024)
                try:
                   json_data = json.loads(data)
                except ValueError:
                   logger.debug("Decode error while decoding json")
                   start_count = start_count + 1
                   json_data = None
                   continue
                break
            if json_data:
                sniffer_details = ['sudo', 'python', json_data['file_name'] ]
                sniffer_details.extend(json_data['arguements'])
                logger.debug("sniffer program started with {0}".format(sniffer_details))
                p = subprocess.Popen(sniffer_details)
            connection.send("end")
        elif data.strip("\r\n") == "stop_packet_sniffing":
            p.send_signal(signal.SIGINT) 
            connection.send("done")
        elif data == "upload_packet_dump":
            import settings
            connection.send("start")
            with open(settings.dump_file, 'rb') as dump_file:
               data = dump_file.read()
            connection.send(len(data))
            connection.send(data)
            response = connection.recv(13)
            if response == 'file received':
                connection.send("end")
        elif data == "send_packet_stats":
            import settings
            connection.send("start")
            send_data = '{"result": "unknown"}'
            p = subprocess.Popen(['sudo', 'python', settings.stats_collect_file])
            p.wait()
            logger.debug("stats collecting program started")
            if p.returncode == 0:
                with open(settings.stats_file, 'r') as stats_file:
                    send_data = stats_file.read()
            connection.send(send_data.replace("'", "\""))
            response = connection.recv(14)
            if response == "stats received":
                connection.send("end")
        else:
           logger.debug("Unknown Command is received")
        connection.close()
