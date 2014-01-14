/*
FileName:	README.txt
Title:		LAB 3: Bit Torrent
Authors:	Chintan Gosalia <cgosalia@indiana.edu>, Awani Marathe <amarathe@indiana.edu>
*/
/*----------------------------------------------------------------------------------------------*/
/*List of all files present */
-----------------------------
1. Makefile
2. bencode.c|h
3. bt lib.c|h
4. bt setup.c|h
5. bt client
6. mylog.log
7. README

/* To Compile Seeder Side */
----------------------------
make all


/*To Run Seeder Side */
-----------------------
./bt_client some_torrent.txt.torrent


/*To Run Leecher Side */
-----------------------
./bt_client -v -p localhost:portnumber -s savefile.txt -l log-file.log some_torrent.txt.torrent


Explanation of the code:
------------------------

CORE BIT TORRENT FUNCIONALITY:

	The code implements 1 seeder and 1 leecher functionality for the bit torrent specification. Following are certain options that are deployed in the code:

Options:
1. at the seeder side: 
	
	a.	-b: 
			-b is just handled, incase the user puts a -b on the command prompt he is told what the -b functionality does 

2. at the leecher side:
	
	a.	-s:
			The value to this option will be the name with which the incoming file will be downloaded.
	b.	-l:
			The value to this option wil be the name of the log file that will be created at the leecher side.
	c.	-p:
			The value here specifies the seeder's ip and the port number on which the seeder is listening for new incoming connections.
	d.	-v:	
			This option will print additional verborse information.

3.
		-h:		
			The option will print the help screen which will display the usage of the options.

Code:
	
1. 	bt_client.c:
		The bt_client.c contains the main function from which the other function will be called.

2.	bt_lib.c:
		It contains most of the important functions used in the project. The additional functions that were added apart from those that were present in the skeleton as follows:

	a.	parse_bt_info:
			This function parses the value of the be_node instance and populates the bt_info instance with values from the torrent file.
	b.	makeSeederListen:
			This function contains the code to define sockets at the seeder side and to make those listen for incoming connections.
	c.	handleHandshaking:
			The code to exchange the handshaking messages amongst the leecher and the seeder can be found in this function.
	d.	initiateExchange:
			The code in this function houses the functionality to exchange the messages between the seeder 
			and the leecher. It may be noted that the data will be sent from the seeder to the leecher in one of the messages (piece message), the code for which can be found here.
	e.	initiateInterest:
			This function will send an interested message from the leecher to the seeder if it is interested in the file the seeder has.
	f.	initiateUnchoked:
			Upon recieving the interested message, the seeder will call this function to unchoke the leecher.
	g.	acceptInterestedMessages:
			This method will be used by the seeder to accept incoming interested message from the leecher.
	h.	acceptUnchokedMessages:
			This method will be used by the leecher to accept incoming unchoked message from the seeder.
	i.	print_status:
			This method will be used by the leecher to print the status messages when each piece is downloaded.
	j.	logging_function:
			This function appends those values to be logged into the log file

3.	bt_setup.c:	
	a.	usage:
			This function will print the help screen when -h option is used or an error occurs.
	b.	_parse_peer:
			This function will parse a char pointer and populates a peer instance with ip and the port.
	c.	parse_args:
			This function will parse the command line argument and populate the bt_args_t instance.



Important points to note:
	1.	The bencode.c has been unchanged.
	2.	Each piece is further divided into blocks of 8kb and each request is made for each of these 8kb chunks. 
		The seeder in turn will send the requested 8kb chunk in response to the requested message.

/*------------------------------------------------------------------------------------------------------*/			