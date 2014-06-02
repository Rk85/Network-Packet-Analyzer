import socket
import subprocess
import signal
import sys
import settings
import json

def creat_socket():
    '''
        Creats new socket and returns it to make new connection
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
        Signal handler function to grace fully exit
    '''
    print 'Stop pressing the CTRL+C!'
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint_handler)
    if "receive_packet_sniffer_file" in sys.argv:
        for file_name in settings.packet_sniffer_files:
            with open(file_name, 'r') as sniffer_file:
                file_data = sniffer_file.read()
            send_data = {'file_name' :  file_name,
                        'file_content' : file_data }
            sender_socket = creat_socket()
            sender_socket.connect(('127.0.0.1', 8081))
            sender_socket.send("receive_packet_sniffer_file")
            response = sender_socket.recv(3)
            if response == 'yes':
                sender_socket.send(json.dumps(send_data))
                response = sender_socket.recv(11)
                if response == "END OF FILE":
                    print "Continuing another file upload"
                    sender_socket.close()
                else:
                    print "Unknown issue, quitting file upload"
                    sender_socket.close()
                    break
                    
