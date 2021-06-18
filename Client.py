from socket import *
import random
import time
serverName = '127.0.0.1'
serverPort = 12000
clientSocket = socket(AF_INET, SOCK_DGRAM)

#Generate packets
flags = ["start", "continue", "end"]

#specific packets to make sure that they met every rule in the firewall
specific_packets = ["200.120.20.12 127.0.0.1 95 12000 start",
                    "127.190.0.40 127.0.0.1 80 12000 continue",
                    "150.40.3.1 127.0.0.1 30 12000 continue",
                    "60.100.2.4 127.0.0.1 90 12000 continue",
                    "127.0.0.150 127.0.0.1 80 12000 start",
                    "200.120.20.20 127.0.0.1 25 12000 end",
                    "150.40.3.1 127.0.0.1 30 12000 end",
                    "180.76.38.1 127.0.0.1 55 12000 start",
                    "192.168.5.1 127.0.0.1 40 12000 continue",
                    "192.168.2.100 127.0.0.1 90 12000 end"]


#try first the specific packets
for i in specific_packets:
    clientSocket.sendto(i.encode(),(serverName,serverPort))
    time.sleep(2)


#geberate random packets
while True:
    #generate random number for each octent in the source ip
    packet = str(random.randint(0,255)) + "."
    for i in range(3):
        n = random.randint(0,255)
        packet = str(packet) + str(n) + "."
        #concatenate dest ip - source port - dest port to the random generated source ip
        # to get the form of ---- source ip  dest ip  source port  dest port  <flag> ----    
    packet = str(packet[:-1] + "  " + serverName + "  " + str(random.randint(1, 100)) + "  " + str(serverPort) + "  " + random.choice(flags))
    clientSocket.sendto(packet.encode(), (serverName,serverPort))
    time.sleep(2)

