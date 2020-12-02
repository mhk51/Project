import select
import socket
import struct
import sys
import os
import time
import matplotlib.pyplot as plt
import random
import speedtest
import subprocess

###########Sources:
#######1. https://github.com/mrahtz/ultra_ping
#######2.https://stackoverflow.com/questions/55716098/enumerate-devices-connected-to-my-router-using-python-3-in-windows
#######3.https://github.com/satoshi03

s = 0 #success
f = 1 #fail
timer = time.perf_counter ###### My timer
class Process():##### Our process   ###Zahraa
    def __init__(self):

        self.RTT_MAX = None
        self.RTT_MIN = None
        self.RTT_Average = None
        self.Packet_Loss = None
        self.Return_Code = None
        self.messages = []
        self.Size_of_Packet = None
        self.Timeout = None
        self.Destination = None
        self.Destination_IP = None
        
    def is_reached(self): ## checking if the destination is reached 
        return self.Return_Code == s #success

    def print_messsages(self):  ## print the output messages
        for msg in self.messages:
            print(msg)
##############
class Tool(): ## class for pinging the needed information #########Zahraa
    def __init__(self, Timeout=1000, Size_of_Packet=55, ID=0, UDP=False, bind=None, q=True):
        self.Timeout = Timeout ## in ms
        self.Size_of_Packet = Size_of_Packet ## in bytes
        self.ID = ID
        self.UDP = UDP
        self.bind = bind
        self.q = q
    
        if ID is None:
            self.ID = os.getpid() & 0xFFFF
        
        self.icmp_echo = 8
        self.Max_Received_ICMP = 2048
        self.Max_Wait_Time = 1000 # ms ### wait before resend
        self.SequenceNumb = 0
    
    def IP_Valid(self, address): ## checking if the IP address we have is valid ##zahraa
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return True
    ######################
    def IP_or_Hostname(self, address): ### checking whether we are inputing the ip address or the hostname and resolve the destination accordingly
        if self.IP_Valid(address):      ###Zahraa
            return address
        return socket.gethostbyname(address)
    ######################
    def Delay(self, SendingTime, ReceivingTime): ####### Bachar ## calculate the difference between the sending time and the recieving time a.k.a delay
        if not SendingTime or not ReceivingTime:
            return -1
        return (ReceivingTime - SendingTime)*1000
    #######################
    def Echo_Msg(self, message): ## print the messages if q is not enabled 
        if self.q:              ##Zahraa
            return
        print(message)
    ########################
    def Init_Packet(self): #####Zahraa
        # creating a packet with the following characteristics
        #Header:8  #code: 8 #checksum: 16 # ID: 16, Sequence:16
        checksum = 0

        # creating a header with checksum =0
        Header = struct.pack("!BBHHH", self.icmp_echo, 0, checksum, self.ID, self.SequenceNumb)

        PadBytes = []
        starting_Value = 0x42
        for i in range(starting_Value, starting_Value + (self.Size_of_Packet-8)):
            PadBytes += [(i & 0xff)]  ##### range 0 to 255
        data = bytearray(PadBytes)

        checksum = self.Checksum(Header + data)

        Header = struct.pack("!BBHHH", self.icmp_echo, 0, checksum, self.ID, self.SequenceNumb)
        return Header + data
    ######################################
    def Checksum(self, SrcString): ############ checksum function ##Zahraa
        Count_limit = (int(len(SrcString)/2))*2
        sum = 0
        Increment = 0
        LowerByte = 0
        HigherByte = 0
        while Increment < Count_limit:
            if (sys.byteorder == "little"):
                LowerByte = SrcString[Increment]
                HigherByte = SrcString[Increment + 1]
            else:
                LowerByte = SrcString[Increment+ 1]
                HigherByte = SrcString[Increment]
            try:     
                sum = sum + (HigherByte * 256 + LowerByte)
            except: 
                sum = sum + (ord(HigherByte) * 256 + ord(LowerByte))
            Increment += 2
        if Count_limit < len(SrcString):
            LowerByte = SrcString[len(SrcString)-1]
            try:     
                sum += LowerByte
            except:   
                sum += ord(LowerByte)

        sum &= 0xffffffff 
        sum = (sum >> 16) + (sum & 0xffff)   
        sum += (sum >> 16)                    
        Result = ~sum & 0xffff               
        Result = socket.htons(Result)
        return Result
    #################################
    def Sending_Packets(self, mysocket, Destination): #### send packets to destination and returns the sending time
                                                        #######Bachar
        packet = self.Init_Packet()
        SendingTime = timer()
        mysocket.sendto(packet, (Destination, 1))
        return SendingTime
    ##########################
    def Init_Socket(self): #### create a socket based on the type we have (UDP or others)
        if self.UDP:        ##Zahraa
            mysocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        else:
            mysocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if self.bind:
            mysocket.bind((self.bind, 0))
        return mysocket
    ########################
    def ICMP_Header(self, packet): ### Parses the header of icmp  ######Zahraa
        pack= struct.unpack("!BBHHH", packet[20:28])

        ICMPHeader = {}
        ICMPHeader["type"] = pack[0]
        ICMPHeader["code"] = pack[1]
        ICMPHeader["checksum"] = pack[2]
        ICMPHeader["packet_id"] = pack[3]
        ICMPHeader["sequence"] = pack[4]
        return ICMPHeader
    ########################
    def IP_Header(self, packet): ### Parses IP header  ######Zahraa 
        pack = struct.unpack("!BBHHHBBHII", packet[:20])

        IPHeader = {}
        IPHeader["version"] = pack[0]
        IPHeader["type"] = pack[1]
        IPHeader["length"] = pack[2]
        IPHeader["id"] = pack[3]
        IPHeader["flags"] = pack[4]
        IPHeader["ttl"] = pack[5]
        IPHeader["protocol"] = pack[6]
        IPHeader["checksum"] = pack[7]
        IPHeader["src_ip"] = pack[8]
        return IPHeader
    ############################
    def Recieving_Packets(self, mysocket):#### receives packets and returns the receiving time
        Timeout = self.Timeout / 1000   ######Bachar
        while True:
            Start = timer()
            Input, Output, Except = select.select([mysocket], [], [], Timeout)
            Duration = (timer() - Start)
            if Input == []:
                return 0, 0, 0, None, None

            packet, address = mysocket.recvfrom(self.Max_Received_ICMP)
            ICMPHeader = self.ICMP_Header(packet)

            ReceivingTime = timer()

            if ICMPHeader["packet_id"] == self.ID: 
                IPHeader = self.IP_Header(packet)
                IP= socket.inet_ntoa(struct.pack("!I", IPHeader["src_ip"]))
                Size_of_Packet= len(packet) - 28
                return ReceivingTime, Size_of_Packet, IP, IPHeader, ICMPHeader

            Timeout = Timeout - Duration

            if Timeout <= 0:
                return 0, 0, 0, None, None
    #######################
    def ping(self, Destination, times=1): ### pinging out the performance measures we want
        # times= number of ping   #####Zahraa
            
            process = Process() ########initializing our process
            process.Timeout = self.Timeout
            process.Destination = Destination
    
            try:
                Destination_IP = self.IP_or_Hostname(Destination) ## assignning IP or host name
            except socket.gaierror:
                msg = "Cannnot resolve {}: Host is Unknown".format(Destination)
                process.messages.append(msg)
                self.Echo_Msg(msg)
                return process
    
            if not Destination_IP:
                process.Return_Code = f  ## if destination Ip is not found, return false
                return process
    
            process.Destination_IP = Destination_IP
    
            
            self.SequenceNumb = 0 # initializing sequence number
            delays = []
    
            msg = "Destination {} ({}): {} Bytes of Data".format(Destination, Destination_IP, self.Size_of_Packet)
            process.messages.append(msg)
            self.Echo_Msg(msg)
    
            for i in range(0, times):
                try:
                    MySocket = self.Init_Socket() # create a socket
                except socket.error as err: ##checking if there is an error in the socket created
                    errtype, errvalue, errtb = sys.exc_info()
                    if err.errno == 1:
                        msg = "{} - Operation is not permitted. Your process is not running as a root: ICMP messages can not be sent.".format(errvalue)
                    else:
                        msg = str(errvalue)
                    self.Echo_Msg(msg)
                    process.messages.append(msg)
                    process.Return_Code = f
                    return process
    
                try:
                    SendingTime = self.Sending_Packets(MySocket, Destination_IP)
                except socket.error as err:  ## error in the socket
                    msg = "General Failure ({})".format(err.args[1])
                    self.Echo_Msg(msg)
                    process.messages.append(msg)
                    MySocket.close()
                    return process
    
                if not SendingTime:  ## if sending time is none, the packet wasn't sent
                    process.Return_Code = Tool.f
                    return process
    
                ReceivingTime, Size_of_Packet, IP, IPHeader, ICMPHeader = self.Recieving_Packets(MySocket)
                MySocket.close()
                delay = self.Delay(SendingTime, ReceivingTime)
    
                
                if ReceivingTime == 0:  ## packet is not recieved
                    msg = "Request Timeout for ICMP Sequence {}".format(self.SequenceNumb)
                    process.messages.append(msg)
                    self.Echo_Msg(msg)
                    process.Return_Code = f
                else:
                    msg = "{} bytes from {}: ICMP Sequence={} ttl={} time={:.3f} ms".format(
                        Size_of_Packet,
                        IP,
                        self.SequenceNumb,
                        IPHeader['ttl'],
                        delay
                    )
                    process.messages.append(msg)
                    self.Echo_Msg(msg)
                    process.Return_Code = s
                    delays.append(delay)
    
                process.Size_of_Packet = Size_of_Packet
                self.SequenceNumb += 1
                if self.Max_Wait_Time > delay:
                    time.sleep((self.Max_Wait_Time - delay)/1000)
    
            process.RTT_MAX = max(delays) if delays else 0.0
            process.RTT_MIN = min(delays) if delays else 0.0
            process.RTT_Average = sum(delays)/len(delays) if delays else 0.0
    
            
            process.messages.append(msg)
            self.Echo_Msg(msg)
    
            msg = "{} packets transmitted, {} packets received, {:.1f}% packet loss".format(
                self.SequenceNumb,
                len(delays),
                (self.SequenceNumb - len(delays)) / self.SequenceNumb * 100
            )
            process.messages.append(msg)
            self.Echo_Msg(msg)
    
            msg = "round-trip minimum time = {:.2f} ms,round-trip average time = {:.2f} ms, round-trip maximum time= {:.2f} ms \n".format(
                process.RTT_MIN, process.RTT_Average, process.RTT_MAX
            )
            process.messages.append(msg)
            self.Echo_Msg(msg)
            process.print_messsages()
            #
            # representation for the number of bytes received and the corresponding Ips
            ## Jad Jawad
            data ={IP : Size_of_Packet}
            Size =list(data.keys())
            Ips = list(data.values())
            
            #fig = plt.figure(figsize = (10,5))  
            plt.figure(1)
            plt.bar(Size, Ips, color ='Red', width = 0.5)
            plt.xlabel("Ip addresses")
            plt.ylabel("Bytes recieved")
            plt.show
            
            #Representation for the RTTs
            data2 ={"Round-trip minimum time":process.RTT_MIN, "Round-trip average time":process.RTT_Average, "Round-trip maximum time":process.RTT_MAX }
            Rtts = list(data2.keys())
            Name =list(data2.values())
            plt.figure(2)
            plt.bar(Rtts, Name, color= "Green", width =0.4)
            plt.xlabel("Round-trips")
            plt.ylabel("Time in ms")
            plt.show

            return process
    def create_packet(self): #Mohammad  #creating a packet according to the ICMP protocol  
        #create a header according to ICMP protocol: type (8), code (8), checksum (16), id (16), sequence (16)
        checksum = 0
        header = struct.pack('bbHHh', self.icmp_echo, 0, checksum, self.ID, 1) #the header is of struct type and the 'bbHHh' is just the type of the struct
        data = ''
        checksum = self.Checksum(header+ data.encode('utf-8'))  #calculated checksum for the above header
        header = struct.pack('bbHHh', self.icmp_echo, 0,socket.htons(checksum), self.ID, 1)  #add back the checksum to the header
        return header + data.encode('utf-8')   #return back packet consisting of header and the encoded data

    def receive_ip(self,sockt):   #Mohammad     we are gonna use a different receiving function since setsockopt uses a different type of packet encoding
        while True:
            ready = select.select([sockt], [], [], 3)  #solve timeout issue of receiving packets using select
            if len(ready[0]) == 0: # timeouted
                return 0
            packet, addr = sockt.recvfrom(1024)  #receive back information about the packet and the address of the router

            header = packet[-8:] #store only the header part of the packet
            p_id = struct.unpack('bbHHh', header)[3] #unpack the packet header and get its ID only which is in 4th position of the tuple
            if p_id == self.ID:    #compare the packet's id to that we sent which we set to '0'
                return addr[0]  #return the address of the router if it matches our packet id
    def Echo_Request(self, host, ttl): #Mohammad
        sockt = self.Init_Socket()  #create a socket for ICMP protocol for the echo request
        sockt.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl) #allow the socket to take care of the packet TTL
        packet = self.create_packet()
                    #icmp protocol doesnt use a specific port so we'll use a random port
        sockt.sendto(packet, (host, random.randint(49152,65535))) #send the created packet to the destination host
            
        timeout = 3 #create timeout constant of 3 seconds
        IP = self.receive_ip(sockt) #get back ip information from the destination host
        sockt.close()
        return IP

    def Traceroute(self, hostname,hops = 30):  #Mohammad
        host = socket.gethostbyname(hostname)   #get IP of our destination host from domain name
        print("Tracerouting for",hostname,"of IP:",host,"with maximum of",hops,"hopes")
        for ttl in range(1,hops+1):  
            ip = self.Echo_Request(host,ttl)   #send an echo request of increasing packet TTL to identify router IPs 
            if(ip == 0):
                print(ttl,"Request Timed Out")
            else:
                print(ttl," ",ip)       #print the TTL and its corresponding router ip
            if(ip == host):        #end if we reached our destination host
                break
        print("Trace Complete")
    def Bandwidth(self):   #Jad Jawad
        st=speedtest.Speedtest()
        DL=st.download() #download speed of the network connection
        Nb = self.NUmber_Of_Users_Wifi()
        print(DL/2**20)
        Bandwidth = "{:.2f}".format(Nb*DL/1000000)
        print("Current Bandwidth is: ",Bandwidth," Mbps")
        print(Nb," devices are connected to this router")

    def NUmber_Of_Users_Wifi(self): #Jad Jawad   #function to get the number of users on the current router
        #code was written with the help of a stackoverflow post that helped find the number of devices connected to the WIFI connection  
        for i in range(20):
            command=['ping', '-n','1', '192.168.1.1'+str(i)] #the IP address in the string is the IP address of the router
            subprocess.call(command)
            #pings all connected devices to the router
            arpa = subprocess.check_output(("arp","-a")).decode("ascii")
            
            devices = len([x for x in arpa.split('\n')if '192.168' in x and all(y not in x for y in ['198.168.1.1'])])
            #enumerates all the devices connected to the router and adds them to a list, but we are only interested in the number of devices connected to the router
            return devices
        
    #Bandwidth of a network is (number of connected users)*(throughtput)
    #since we want the max amount of data trasmitted over an internet connection
############################ representation

############################ testing
#def main():
p = Tool()

hostname = input("Please input hostname/address: \n")

p.ping(hostname)
p.Traceroute(hostname)
p.Bandwidth()
