# myPING

The goal of this assignment is to familiarize you with the low-level operations of the Internet protocol stack. Thus far, 
you have had experience using sockets and manipulating application level protocols. However, working above the operating 
system's networking stack hides all the underlying complexity of creating and managing packet headers.

Your task is to write a ping program that takes a domain name or ipv4 address of a destination host on the command line 
and send an ICMP messages to the destination host. Specifically,

* Your ping program is to send 3 ping messages to the target host over ICMP. For each message, your client is to 
determine and print the RTT when the corresponding pong message is returned.
* Your ping program will also output the min, max, and average RTTs at the end.
* You ping program will need to create the ICMP headers for each ping message.
* Be careful with the checksum field, you need to guarantee the checksum value is correct in the ICMP header. 
* You can use Wireshark to debug your program to check the pong message is returned or not.


## Getting Started
* Unpack zip file and change into that directory

### Prerequisities
* BSD implimentation of ICMP ping using RAW sockets. 
* I am pretty sure this will only work on BSD and macOSX machines without changing around the 
IP and ICMP struct's.

## Compile
TO BUILD:
```
gcc -o myPING myPING.c
```

USAGE:
```
Usage: myPING [destination] <-s [source]>
Destination must be provided
Source is optional
To add source, add -s flag
```

TO RUN (example):
```
sudo ./myPING www.google.com
```

## Authors
* **Spencer Kitchen** 


