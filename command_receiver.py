import select, socket
import subprocess
import signal
import sys

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
        if data.strip("\r\n") == "start":
           p = subprocess.Popen(['python', 'sniff_packet.py', 'interface', 'eth0', 'port', '80'])
        elif data.strip("\r\n") == "stop":
           p.send_signal(signal.SIGINT) 
        elif data == "upload":
           pass
        else:
           print "Unknown Command"
        connection.close()
