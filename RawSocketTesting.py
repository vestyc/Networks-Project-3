import socket
import struct

# the public network interface
HOST = socket.gethostbyname(socket.gethostname())

# create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while(True):
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
    #print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

    if protocol == 6:
        tcp_header = packet[iph_length:iph_length+20]
             
        #now unpack them :)
        tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
             
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
             
        print("TCP")     
        print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
            
        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size
             
        #get data from the packet
        data = packet[h_size:]
             
        #print ('Data : ' + data.strip().decode('utf-8'))

    elif protocol == 17:
        udp_header = packet[iph_length:iph_length+8]
        udph = struct.unpack('!HHHH', udp_header);

        #unpacking
        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]

        print("UDP")
        print('Source Port: ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length: ' + str(length) + ' Checksum : ' + str(checksum))

    
