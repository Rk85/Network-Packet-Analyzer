import select, socket
import subprocess
import signal
import sys
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
    server_socket = creat_socket()
    server_socket.bind(('0.0.0.0', 8081))
    server_socket.listen(1)
    p = ''
    while True:
        connection, address = server_socket.accept()
        data = connection.recv(1024)
        print "Request", data, len(data)
        if data == "check_alive":
            connection.send("yes")
        elif data == "start_packet_sniffing":
            connection.send("start")
            data = ""
            while True:
                data = data + connection.recv(1024)
                print data
                try:
                   json_data = json.loads(data)
                except ValueError:
                   print "Decode error"
                   continue
                finally:
                   print "decode_error_solved"
                   sniffer_details = ['sudo', 'python', json_data['file_name'] ]
                   sniffer_details.extend(json_data['arguements'])
                   print sniffer_details
                   p = subprocess.Popen(sniffer_details)
                   connection.send("end")
                   break
        elif data.strip("\r\n") == "stop_packet_sniffing":
            p.send_signal(signal.SIGINT) 
            connection.send("done")
        elif data == "upload_packet_dump":
            connection.send("start")
            with open(settings.dump_file, 'rb') as dump_file:
               data = dump_file.read()
            connection.send(len(data))
            connection.send(data)
            response = connection.recv(13)
            if response == 'file received':
                connection.send("end")
        elif data == "send_packet_stats":
            connection.send("start")
            send_data = { 'stats': 'yes'}
            sender_socket.send(json.dumps(send_data))
            response = connection.recv(14)
            if response == "stats received":
                connection.send("end")
        elif data == "receive_packet_sniffer_file":
            connection.send("start")
            data = ""
            while True:
                data = data + connection.recv(1024)
                try:
                   json_data = json.loads(data)
                except ValueError:
                   print "Decode error"
                   continue
                finally:
                    with open(json_data['file_name'], 'w') as sniffer_file:
                        sniffer_file.write(json_data['file_content'])
                        connection.send("end")
                        break
        else:
            print "Unknown Command"
        connection.close()
