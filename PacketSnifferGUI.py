from Tkinter import *
import Tkinter
import time
import socket
import struct

window = Tkinter.Tk()
window.title("Packet Sniffer")
window.geometry("1000x750")

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0003))

i = 0
running = BooleanVar()
running.set(True)
label = StringVar()
label.set('CLICK START TO BEGIN...')

def start():
    global i 
    label.set('SNIFFING...')
    if running.get():
        # receive a package
        packet = s.recvfrom(65565)
    
        #packet string from tuple
        packet = packet[0]
         
        #take first 20 characters for the ip header
        ip_header = packet[0:20]
         
        #now unpack them :)
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
         
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
         
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
         
        #print ("IP")
        ip_output = str(i) + ' IP ' + 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        print (ip_output)
        listbox.insert(END,ip_output)

        if protocol == 6:
            tcp_header = packet[iph_length:iph_length+20]
             
            #now unpack them
            tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
             
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
             
            #print("TCP")
            tcp_output = str(i) + ' TCP ' + 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
            print(tcp_output)
            listbox.insert(END,tcp_output)
            
            h_size = iph_length + tcph_length * 4
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
             
            #check for http
            if dest_port == 80:
                #unpack http
                http = packet[iph_length+20:len(packet)]
                print(http)
                listbox.insert(END,str(i) + ' HTTP ' + tcp_output)

        elif protocol == 17:
            udp_header = packet[iph_length:iph_length+8]
            udph = struct.unpack('!HHHH', udp_header);

        #unpacking
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            #print("UDP")
            udp_output = str(i) + ' UDP ' + 'Source Port: ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length: ' + str(length) + ' Checksum : ' + str(checksum)
            print(udp_output)
            listbox.insert(END,udp_output)

        elif protocol == 1:
            icmp_header = packet[iph_length:iph_length+8]
            icmph = struct.unpack('!BBHHH', icmp_header);

        #unpacking
            icmp_type = icmph[0]
            icmp_code = icmph[1]
            icmp_checksum = icmph[2]
            icmp_identifier = icmph[3]
            icmp_seqnum = icmph[4]
            #print("ICMP")
            icmp_output = str(i) + ' ICMP ' + 'Type: ' + str(icmp_type) + ' Code: ' + str(icmp_code) + ' Checksum: ' + str(icmp_checksum)
            icmp_output = icmp_output + 'Identifier: ' + str(icmp_identifier) + ' Sequence Number: ' + str(icmp_seqnum)
            listbox.insert(END,icmp_output)
        i = i+1    
        window.after(10,start)
    else:
        running.set(False)
        label.set('STOPPED')
    window.update_idletasks()
    
def stop():
    running.set(False)
    label.set('STOPPED')
    window.update_idletasks()
    
lbl = Tkinter.Label(window,textvariable=label)
lbl.pack()
startButton = Tkinter.Button(window, text="START", command=start)
stopButton = Tkinter.Button(window, text="STOP", command=stop)
startButton.pack()
stopButton.pack()
scrollbar = Scrollbar(window)
scrollbar.pack(side=RIGHT, fill=Y)
listbox = Listbox(window, bd=5,selectmode=BROWSE, relief=SUNKEN)
listbox.pack(fill=BOTH,expand= TRUE)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)
                         
window.mainloop()
 
