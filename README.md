This is a centralized  web application to find the solution for the following  problem 
	1. To find whether a particular client machine is alive or not
	2. To find/sniff the traffic that is going through the client machines
	2. Details of the traffic that is happening on each client machines

Requirement:
	It requires Couch DB on the server machine
	It requires pcapy python module on client machines

Server Side installation:
	Please refer the following link to install the Couch DB server 
		* http://wiki.apache.org/couchdb/Installation

Client Side installation:
    install the pcapy module using following command in client machines
		* sudo apt-get install python-setuptools
        * sudo easy_install pip
        * sudo pip install pcapy

To Start Server:
	Start the Couch DB in server machine
	Start the web server using command
		* sudo python web_gui_server.py &

To Start Client:
	Copy the following command_receiver.py python file to client madchines
	run the python file with root priviledge ( to listen on interfaces )

open the following URL in web browser 
	http://127.0.0.1:5000/

That's it. everything is set and you are ready to sniff the client packets
