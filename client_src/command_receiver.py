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
        print "Request", data
        if data == "start_packet_sniffing":
            connection.send("yes")
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
                   connection.send("END OF FILE")
                   break
        elif data.strip("\r\n") == "stop_packet_sniffing":
           p.send_signal(signal.SIGINT) 
           connection.send("yes")
        elif data == "upload_packet_dump":
           #with open(settings.dump_file, 'rb') as dump_file:
           #    data = dump_file.read()
           #    connection.send(data)
           pass
        elif data == "send_packet_stats":
           pass
        elif data == "receive_packet_sniffer_file":
            connection.send("yes")
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
                        connection.send("END OF FILE")
                        break
        else:
           print "Unknown Command"
        connection.close()
