################################################
#   CSE 4344 : Computer Network Organization   #
#                  Project 3                   #
#              - Packet Sniffer -              #
#                                              #
# Team Members:                                #
# - Johnny Tran                                #
# - Aaqif Muhtasim                             #
# - Ariel Widjaja                              #
# - Omair Sunka                                #
# - Amado Jose                                 #
################################################

############################
#     Import Libraries     #
############################

from Tkinter import *
import Tkinter
import time
import socket
import struct
import binascii
import matplotlib
import tkFileDialog
matplotlib.use('TkAgg')

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

import sys


class SimplePlot(Tkinter.Canvas):
	def plot(self,x,y):
		self.create_line((x,y,x+1,y), fill = "black")

############################
#      Create Window       #
############################
window = Tkinter.Tk()
window.title("Packet Sniffer")
window.geometry("1000x750")

root = Tkinter.Toplevel()
root.title("Throughput Graph")
root.geometry("1000x750")

############################
#   Global Variables       #
############################

totaldata = 0
st =0
n = 1
datacount = 0
timelist = list()
datalist = list()
timestart = time.time()
i = 0

############################
#   Create a Raw Socket    #
############################

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
running = BooleanVar()
running.set(True)
label = StringVar()
label.set('CLICK START TO BEGIN...')
label1 = StringVar()
label1.set(' ')

##############################
#  Function : Stop Sniffing  #
##############################

def stop():
	averageThroughput = totaldata/(n-1)
	a.plot(timelist, datalist)
	a.set_xlabel('Time (seconds)')
	a.set_ylabel('Data (bytes)')
	canvas = FigureCanvasTkAgg(f, master=root)
	canvas.show()
	canvas.get_tk_widget().pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
	canvas._tkcanvas.pack(side=Tkinter.TOP, fill=Tkinter.BOTH, expand=1)
	button = Tkinter.Button(master=root, text='Quit', command=sys.exit)
	button.pack(side=Tkinter.BOTTOM)
	running.set(False)
	label.set('STOPPED')
	label1.set('Average throughput (bytes/s): ' + str(averageThroughput))
	window.update_idletasks()

##############################
#  Funtion : Start Sniffing  #
##############################

def start():
	global st
	global timestart
	global timelist
	global datalist
	global a
	global f
	global n
	global totaldata
	global datacount
	if st ==0:
		timestart = time.time()
		st =1
	
	global i 
	label.set('SNIFFING...')
	if running.get():

                ############################
                #     Receive Packets      #
                ############################
          
		f = Figure(figsize=(5, 4), dpi=100)
		a = f.add_subplot(111)

		      
		packet = s.recvfrom(65565)
		packet = packet[0]
		datacount = datacount + len(packet)
		totaldata = totaldata + len(packet)
		timecurr = time.time() - timestart
		if(timecurr >= 1.0):
			st = 0
			timelist.append(n)
			datalist.append(datacount)
			datacount = 0
			n = n + 1

          ############################
		#         Ethernet         #
		#        (14 Bytes)        #
		############################
		
		eth_header = packet[0:14]
	
		# Unpacking Ethernet Header
		eh = struct.unpack('!6s6sH', eth_header)

		# Destination MAC Address
		eth_dest = binascii.hexlify(eh[0])

		# Source MAC Address
		eth_src = binascii.hexlify(eh[1])

		# Type
		eth_type = eh[2]

		# Print Ethernet Header Fields
		eth_output = 'Ethernet - ' + 'MAC Dest : ' + str(eth_dest) + ' MAC Src : ' + str(eth_src) + ' Ethernet Type : ' + str(eth_type)
		listbox.insert(END,eth_output)

          ############################
		#  Internet Protocol (IP)  #
		#         (20 Bytes)       #
		############################
		
		if eth_type == 0x0800:
			ip_header = packet[14:34]
			 
			# Unpacking IP Header
			iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

			# Version and Header Length
			version_ihl = iph[0]
			version = version_ihl >> 4
			ihl = version_ihl & 0xF
		
			iph_length = ihl * 4
			iph_length = iph_length + 14

			# Time To Live 
			ttl = iph[5]

			# Protocol
			protocol = iph[6]

			# Source IP Address
			s_addr = socket.inet_ntoa(iph[8]);

			# Destination IP Address
			d_addr = socket.inet_ntoa(iph[9]);
			 
			# Print IP Header Fields
			ip_output = 'IP - ' + 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
			listbox.insert(END,ip_output)
		           
                        ########################################
			#  Transmission Control Prorocol (TCP) #
			#                 (20 Bytes)           #
			########################################
			
			if protocol == 6:
				tcp_header = packet[iph_length:iph_length+20]
				
				# Unpacking TCP Header
				tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

		                # Source Port Number
				source_port = tcph[0]

				# Destination Port Number
				dest_port = tcph[1]

				# Sequence Number
				sequence = tcph[2]

				# Acknowledgment Number
				acknowledgement = tcph[3]

				# Offset and Reserved
				doff_reserved = tcph[4]

				# TCP Header Length
				tcph_length = doff_reserved >> 4
				
				# Print TCP Header Fields
				tcp_output = 'TCP - ' + 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)       
				listbox.insert(END,tcp_output)
		                   
		                # Data Size
				h_size = iph_length + tcph_length * 4
				data_size = len(packet) - h_size
					
				# Get Data from the Packet
				data = packet[h_size:]
				
                                ########################################
				#   Hypertext Tranfer Protocol (HTTP)  #
				########################################
				
				if dest_port == 80:
					# Unpacking HTTP
					http = packet[iph_length+20:len(packet)]
					if http:
						http1 = " ".join(http.split("\r\n"))
						listbox.insert(END,'HTTP - ' + http1)

                        ########################################
			#      User Datagram Protocol (UDP)    #
			#              (8 Bytes)               #
			########################################
			
			elif protocol == 17:
				udp_header = packet[iph_length:iph_length+8]
		                   
		                # Unpacking UDP Header
				udph = struct.unpack('!HHHH', udp_header);

				# Source Port Number
				source_port = udph[0]

				# Destination Port Number
				dest_port = udph[1]

		                # Length
				length = udph[2]

		                # Checksum
				checksum = udph[3]

				# Print UDP Header Fields
				udp_output = 'UDP - ' + 'Source Port: ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length: ' + str(length) + ' Checksum : ' + str(checksum)
				listbox.insert(END,udp_output)

                        ##############################################
			#  Internet Control Message Protocol (ICMP)  #
			#                   (8 Bytes)                #
			##############################################
			
			elif protocol == 1:
				icmp_header = packet[iph_length:iph_length+8]

				# Unpacking ICMP Header
				icmph = struct.unpack('!BBHHH', icmp_header);

				# Type
				icmp_type = icmph[0]

		                # Code
				icmp_code = icmph[1]

				# Checksum
				icmp_checksum = icmph[2]

		                # Identifier
				icmp_identifier = icmph[3]

		                # Sequence Number
				icmp_seqnum = icmph[4]

				# Print ICMP Header Fields
				icmp_output = 'ICMP - ' + 'Type: ' + str(icmp_type) + ' Code: ' + str(icmp_code) + ' Checksum: ' + str(icmp_checksum)
				icmp_output = icmp_output + 'Identifier: ' + str(icmp_identifier) + ' Sequence Number: ' + str(icmp_seqnum)       
				listbox.insert(END,icmp_output)

                ########################################
		#   Address Resolution Protocol (ARP)  #
		#              (28 Bytes)              #
		########################################
		
		elif eth_type == 0x0806:    
			arp_packet = packet[14:42]

			# Unpacking ARP Header
			arp_header = struct.unpack('!HHBBH6s4s6s4s', arp_packet)
		
			# Hardware Type
			hardware_type = arp_header[0]

		        # Protocol Type
			protocol_type = arp_header[1]

			# Hardware Address Length
			hardware_size = arp_header[2]

		        # Protocol Address Length
			protocol_size = arp_header[3]

			# Opcode
			opcode = arp_header[4]

		        # Source MAC Address
			src_mac = binascii.hexlify(arp_header[5])

			# Source IP Address
			src_ip = socket.inet_ntoa(arp_header[6])

			# Destination MAC Address
			dest_mac = binascii.hexlify(arp_header[7])

		        # Destination MAC Address
			dest_ip = socket.inet_ntoa(arp_header[8])

			# Print ARP Header Fields
			arp_output = 'ARP - ' + 'Hardware Type: ' + str(hardware_type) + ' Protocol Type: ' + str(protocol_type) + ' Hardware Size: ' + str(hardware_size) + ' Protocol Size: ' + str(protocol_size) + ' Opcode: ' + str(opcode) + ' Src MAC: ' + str(src_mac) + ' Src IP: ' + str(src_ip) + ' Dest MAC: ' + str(dest_mac) + ' Dest IP: ' + str(dest_ip)
			listbox.insert(END,arp_output)
		listbox.insert(END,'*******************************************************************************************************************')
		listbox.see(END)
		i = i+1    
		window.after(10,start)
	else:
		running.set(False)
		label.set('STOPPED')
	window.update_idletasks()
    
########################################
#            Implementing GUI          #
########################################

lbl1=Tkinter.Label(root,textvariable=label1)
lbl1.pack()

lbl = Tkinter.Label(window,textvariable=label)
lbl.pack()
# Create Start Button
startButton = Tkinter.Button(window, text="START", command=start)
startButton.pack()

# Create Stop Button
stopButton = Tkinter.Button(window, text="STOP", command=stop)
stopButton.pack()

# Create Vertical Scrollbar
yscrollbar = Scrollbar(window)
yscrollbar.pack(side=RIGHT, fill=Y)

# Create Horizontal Scrollbar
xscrollbar = Scrollbar(window,orient=HORIZONTAL)
xscrollbar.pack(side=BOTTOM,fill=X)

# Create Listbox
listbox = Listbox(window, bd=5,selectmode=DISABLED, relief=SUNKEN)
listbox.pack(fill=BOTH,expand= TRUE)
listbox.config(yscrollcommand=yscrollbar.set)
listbox.config(xscrollcommand=xscrollbar.set)

# Configure Vertical and Horizontal ScrollBars
yscrollbar.config(command=listbox.yview)
xscrollbar.config(command=listbox.xview)

window.mainloop()
root.mainloop()
 
