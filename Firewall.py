import ipaddress
from socket import *

serverPort = 12000
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('localhost', serverPort))

#rule set
rules = ["allow 127.0.0.0/24 80",
         "block * 80",
         "allow 192.168.2.0/24 *",
         "block * 90 established",
         "allow * 40 established",
         "allow * 25",
         "allow 200.120.20.0/23 *",
         "allow * 55",
         "allow 0.0.0.0/0 30",
         "block * * established",
         "block * *"]


#this function for check each packet will match wich rule
def checkIpWithRule(IPaddress, Port, packetFlag):
    #to go through the rule set
    for rule in rules:
        rule_length = len(rule.split(" "))
        #check rules that not ended with modifier 'established'
        if(rule_length == 3):
            if (rule.split(" ")[1] == '*'):
                if((rule.split(" ")[2] == '*') or (rule.split(" ")[2] == Port)):
                    print(f"IP Packet: {IPaddress}\tPort: {Port}\nTargeted Rule: {rule}\n\n")
                    break
            elif(ipaddress.ip_address(IPaddress) in ipaddress.ip_network(rule.split(" ")[1])):
                if((rule.split(" ")[2] == '*') or (rule.split(" ")[2] == Port)):
                     print(f"IP Packet: {IPaddress}\tPort: {Port}\nTargeted Rule: {rule}\n\n")
                     break
        #check rules that ended with modifier 'established'
        elif(rule_length == 4):
            if(packetFlag == "continue"):
                if(rule.split(" ")[1] == '*'):
                    if((rule.split(" ")[2] == '*') or (rule.split(" ")[2] == Port)):
                        print(f"IP Packet: {IPaddress}\tPort: {Port}\nTargeted Rule: {rule}\n\n")
                        break

                elif((ipaddress.ip_address(IPaddress) in ipaddress.ip_network(rule.split(" ")[1])) and (packetFlag == "continue")):
                    if((rule.split(" ")[2] == '*') or (rule.split(" ")[2] == Port)):
                        print(f"IP Packet: {IPaddress}\tPort: {Port}\nTargeted Rule: {rule}\n\n")
                        break
while 1:
    targetMessage, clientAddress = serverSocket.recvfrom(2048)
    IPaddress = list(filter(None, targetMessage.decode().split(" ")))[0]
    Ipaddress_port = list(filter(None, targetMessage.decode().split(" ")))[2]
    IPaddress_packetFlag = list(filter(None, targetMessage.decode().split(" ")))[4]
    checkIpWithRule(IPaddress, Ipaddress_port, IPaddress_packetFlag)








        

