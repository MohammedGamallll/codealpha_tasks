import scapy
from scapy.all import *

def analyze(packet):
    try:
        if packet.haslayer(TCP):
            print("______________________________________________________\n")
            print("<< TCP PACKET >>")
            print("IP OF SOURCE : " + packet[IP].src)
            print("IP OF DESTINATION : " + packet[IP].dst)
            print("MAC-ADDRESS of SOURCE : " + packet.src)
            print("MAC-ADDRESS OF DESTINATION : " + packet.dst)
            print("PORT NUMBER OF SOURCE : " + str(packet.sport))
            print("PORT NUMBER OF DESTINATION : " + str(packet.dport))
            print("LENGTH OF PACKET : " + str(len(packet[TCP])) + " byte")
            
            if packet.haslayer(Raw):   
                print("DATA OF PACKET : ")
                print(packet[Raw].load)   

        if packet.haslayer(UDP):
            print("______________________________________________________\n")
            print("<< UDP PACKET >>")
            print("IP OF SOURCE : " + packet[IP].src)
            print("IP OF DESTINATION : " + packet[IP].dst)
            print("MAC-ADDRESS of SOURCE : " + packet.src)
            print("MAC-ADDRESS OF DESTINATION : " + packet.dst)
            print("PORT NUMBER OF SOURCE : " + str(packet.sport))
            print("PORT NUMBER OF DESTINATION : " + str(packet.dport))
            print("LENGTH OF PACKET : " + str(len(packet[UDP])) + " byte")

            if packet.haslayer(Raw):   
                print("DATA OF PACKET : ")
                print(packet[Raw].load) 

        if packet.haslayer(ICMP):
            print("______________________________________________________\n")
            print("<< ICMP PACKET >>")
            print("IP OF SOURCE : " + packet[IP].src)
            print("IP OF DESTINATION : " + packet[IP].dst)
            print("MAC-ADDRESS of SOURCE : " + packet.src)
            print("MAC-ADDRESS OF DESTINATION : " + packet.dst)
            print("LENGTH OF PACKET : " + str(len(packet[ICMP])) + " byte")
            
            if packet.haslayer(Raw):   
                print("DATA OF PACKET : ")
                print(packet[Raw].load) 


    except Exception as e:
         print(f"Error: {e}")
       

sniff(iface="eth0", prn=analyze)
