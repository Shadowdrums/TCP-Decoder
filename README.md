# TCP-Decoder
Monitors tcp traffic and trys to decode the packets  

This program is a Python script that captures and decrypts network traffic using the Scapy library. The purpose of the program is to demonstrate how to decode network traffic payloads that have been encrypted using a particular network key.

The program consists of three main functions: find_network_key(), decode_packet(), and capture_traffic().

The find_network_key() function searches for the network key on the device by running the netsh command to show the available Wi-Fi profiles and their network keys. It then loops through each profile, running the netsh command again to show the key content of each profile. If it finds a profile with a network key, it returns the key.

The decode_packet() function takes a packet and the network key as input and attempts to decode the payload of the packet. If the packet is a TCP packet, it extracts the source IP address, source port, and payload. It then attempts to decrypt the payload using the network key and prints the decrypted payload to the console. If decryption fails, it prints a message indicating that the payload could not be decrypted. If the packet is an ICMP ping request, it extracts the source IP address and payload. It then attempts to decode the payload and prints the result to the console.

The capture_traffic() function takes the network key as input and uses the Scapy sniff() function to capture network traffic. It filters the traffic to only capture TCP packets and ICMP ping requests. For each packet that is captured, it calls the decode_packet() function to attempt to decode the payload.

At the end of the script, the find_network_key() function is called to search for the network key. If the function returns None, the script prints a message indicating that it was unable to find the network key. Otherwise, the capture_traffic() function is called to capture and decode network traffic using the network key.
