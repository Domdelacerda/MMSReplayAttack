PETER HAHM - 5/13/24

-- BACKGROUND --
During the semester of Spring 2024 we were able to successfully view a GOOSE trip message in Wireshark,
capture it, replay it with the correct modifications (spoof it), and get the same breaker to trip with
this spoofed message. The issue with this is that the GOOSE protocol operates on the link layer, which
means that (1) remote usage of our spoofed message literally won't go anywhere and (2) if we had local
access to where we could use a link-layer attack, we might as well just shoot the server. Therefore we
were interested to see if we could find an exploit that could modifiy substation operations remotely.

-- NEW IDEA --
The Manufacturing Message Specification (MMS) protocol is also used in substation microgrid contexts
like the GOOSE protocl, except that it operates at the IP layer. Also like GOOSE, MMS messages can be
sent to modifiy subtation operations (such as trip a breaker). Therefore by extension it is reasonable
to assume that a successfully spoof of the MMS trip message may be able to modify substation operations
remotely, outside of the local substation network.

-- CAPTURING THE MMS TRIP --
Zenon Engineering Studio is a program used to create programs that view and manage SCADA and SCADA-like
systems such as the substation microgrid environment relevant to this research. Using a tutorial that
you can ask Dr. Ma about, you can set up a program to send MMS trip messages to the microgrid to trip
a breaker in the same way that GOOSE messages do. A program to do this was configured, and the MMS trip
message was captured using Wireshark.

-- HOW TO SPOOF --
At first the same approach to the GOOSE trip was used, which means just replaying the specific trip
packet recieved. This did not work, and it is believed to be because MMS is connection-orientated (or
at least that's how it appears to be used here). Before the trip message is sent from the Zenon
program, several communication exchanges take place between the Zenon program and the target ABB
device. It seems that these communication exchanges may be neccessary to fully "set up" the connection
before any configuration messages, such as a trip, can be sent. The first of these communication
exchanges appears to be a stanard 3-way TCP handshake which establishes the TCP connection on which
the rest of the communication takes place. A 3-way handshake was succesfully done with a python script,
and the trip packet was successfully constructed and sent over this connection, but to no avail. This
is not surprising, and seems to indicate that there are several more communication exchanges that need
to be properly spoofed before the trip packet can be sent over the connection. This is where the
Spring 2024 research concluded.

-- FILES --
mms_remote_trip_and_startup.pcapng
	> The Wireshark capture of the Zenon program initiating an MMS connection with the target
	> ABB device and sending the trip message (I believe sending it twice).
MMS_Replay_Unfinished.py
	> The Python program to perform a 3-way TCP handshake with the target ABB device and then
	> send the trip packet over this connection. Comments denote each section but assueme the
	> reader has read this document beforehand for context.

-- CONTACT --
If you have any questions feel free to reach out to me, Peter Hahm, at hahmp@uwplatt.edu.

DOMINIC DE LA CERDA - 3/5/25

-- CONTINUED WORK --
In addition to the TCP handshake, two more upper layer connections must be made: a COTP connect 
request and an MMS associate request. Both connection requests can be spoofed byte-for-byte from
the captured packets and require no modifications for the purposes of this attack. The trip packet
consists of two separate MMS set data value request packets sent in sequence. Two packets are required
because tripping the breaker is a "select before operate" command, meaning the first packet is a 
select statement and the second packet is the trip operation. The two packets are not the exact same
as they have different item IDs and invoke IDs. Each set data value request requires a UTC timestamp
with precision in the nanoseconds in order for object access to be granted. A program to spoof each
requests' timestamp was configured and the attack was able to successfully trip the REF615 breaker.

-- FILES --
mms_trip_success.pcapng
	> The Wireshark capture of the full attack, consisting of the TCP three-way handshake, the
	> COTP connect request and response, the MMS associate request and response, the two MMS
 	> set data value requests and their responses, and the unconfirmed command termination
  	> response indicating a successful trip.
MMS_Replay_Finished.py
	> The Python program to perform the full attack. IP addresses for the attacker and the
 	> server can be modified as needed.
