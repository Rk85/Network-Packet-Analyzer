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
    argements = json.loads(sys.argv[1])
    print argements
    ip = argements['ip']
    port = argements['port']
    signal.signal(signal.SIGINT, sigint_handler)
    if argements.get('command_to_send') == "check_alive":
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("check_alive")
        response = sender_socket.recv(3)
        if response == "yes":
            sender_socket.close()
    if argements.get('command_to_send') == "receive_packet_sniffer_file":
        for file_name in settings.upload_sniffer_files:
            with open(file_name, 'r') as sniffer_file:
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
                    print "Continuing another file upload"
                    sender_socket.close()
                else:
                    print "Unknown issue, quitting file upload"
                    sender_socket.close()
                    break
    if argements.get('command_to_send') == "start_packet_sniffing":
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("start_packet_sniffing")
        response = sender_socket.recv(5)
        print "RESP", response
        if response == 'start':                
            send_data = { 'file_name' : settings.sniffer_file,
                          'arguements' : ['interface', 'lo', 'port', '80']
                        }
            sender_socket.send(json.dumps(send_data))
            response = sender_socket.recv(3)
            if response == "end":
                print "Sniffing Program details have been sent"
                sender_socket.close()
    if argements.get('command_to_send') == "stop_packet_sniffing":  
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("stop_packet_sniffing")
        response = sender_socket.recv(3)
        if response == 'done':
            print "Sniffer program successfully stopped"
    if argements.get('command_to_send') == "upload_packet_dump":
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("upload_packet_dump")
        response = sender_socket.recv(5)
        print "RESP", response
        if response == 'start':
            file_size = sender_socket.recv(100)
            data = ''
            while data != int(file_size):
                data = data + sender_socket.recv(file_size)
            sender_socket.send('file received')
            sender_socket.recv(100)
            if response == "end":
                print "Packet dump is received"
                sender_socket.close()
            else:
                print "Unknown issue while uploading packet dump"
    if argements.get('command_to_send') == "send_packet_stats":
        sender_socket = creat_socket()
        sender_socket.connect((ip, port))
        sender_socket.send("send_packet_stats")
        response = sender_socket.recv(5)
        if response == 'start':
            data = ""
            while True:
                data = data + sender_socket.recv(1024)
                try:
                   json_data = json.loads(data)
                except ValueError:
                   print "Decode error"
                   continue
                finally:
                    print json_data
                    sender_socket.send("stats received")
                    break
            if response == "end":
                print "Packet dump is received"
                sender_socket.close()
            else:
                print "Unknown issue while packet stats"
