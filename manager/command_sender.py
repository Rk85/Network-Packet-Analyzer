import socket
import subprocess
import signal
import sys
import settings
import json
from db_access import upload_document, retrive_document_details
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

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
        new_socket.settimeout(30)
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

# Register Signal handler
signal.signal(signal.SIGINT, sigint_handler)

if __name__ == "__main__":
    arguements = json.loads(sys.argv[1])
    ip = arguements['ip']
    port = arguements['port']
    if arguements.get('command_to_send') == "check_alive":
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("check_alive")
        response = sender_socket.recv(3)
        if response == "yes":
            sender_socket.close()
    if arguements.get('command_to_send') == "receive_packet_sniffer_file":
        for file_name in settings.upload_sniffer_files:
            with open(settings.SNIFFER_FOLDER + "/" + file_name, 'r') as sniffer_file:
                file_data = sniffer_file.read()
            send_data = {'file_name' :  file_name,
                        'file_content' : file_data }
            sender_socket = creat_socket()
            sender_socket.connect((ip, port))
            sender_socket.send("receive_packet_sniffer_file")
            response = sender_socket.recv(5)
            if response == 'start':
                sender_socket.send(json.dumps(send_data))
                response = sender_socket.recv(3)
                if response == "end":
                    logger.debug("Continuing another file upload")
                    sender_socket.close()
                else:
                    logger.debug("Unknown issue, quitting file upload")
                    sender_socket.close()
                    break
    if arguements.get('command_to_send') == "start_packet_sniffing":
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("start_packet_sniffing")
        response = sender_socket.recv(5)
        if response == 'start':                
            send_data = { 'file_name' : settings.sniffer_file,
                          'arguements' : arguements['capture_rules']
                        }
            sender_socket.send(json.dumps(send_data))
            response = sender_socket.recv(3)
            if response == "end":
                logger.debug("Sniffing Program details have been sent")
                sender_socket.close()
    if arguements.get('command_to_send') == "stop_packet_sniffing":  
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("stop_packet_sniffing")
        response = sender_socket.recv(3)
        if response == 'done':
            logger.debug("Sniffer program successfully stopped")
    if arguements.get('command_to_send') == "upload_packet_dump":
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("upload_packet_dump")
        response = sender_socket.recv(5)
        if response == 'start':
            file_size = sender_socket.recv(100)
            data = ''
            while data != int(file_size):
                data = data + sender_socket.recv(file_size)
            sender_socket.send('file received')
            sender_socket.recv(100)
            if response == "end":
                logger.debug("Packet dump is received")
                sender_socket.close()
            else:
                logger.debug("Unknown issue while uploading packet dump")
    if arguements.get('command_to_send') == "send_packet_stats":
        max_count = 100
        start_count = 0
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("send_packet_stats")
        response = sender_socket.recv(5)
        if response == 'start':
            data = ""
            while start_count <= max_count:
                data = data + sender_socket.recv(1024)
                try:
                   json_data = json.loads(data)
                except ValueError:
                   logger.debug("Decode error while decoding json data")
                   start_count = start_count + 1
                   json_data = None
                   continue
                break
            if json_data:
                result = retrive_document_details({
                        'url': arguements['url']
                })
                if result.get('response_code') == 200:
                    document = result.get('document_data')
                    document['stats'] = json_data
                    document_args = {
                        'url': arguements['url'],
                        'data' : json.dumps(document),
                        'override_doc' : True
                    }
                    upload_document(document_args)
            sender_socket.send("stats received")
            response = sender_socket.recv(3)
            if response == "end":
                logger.debug("Stats are received")
                sender_socket.close()
            else:
                logger.debug("Unknown issue while packet stats")
