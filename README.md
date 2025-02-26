# C Packet Sniffer

## Overview
This is a simple network packet sniffer written in C using `libpcap`. It captures and analyzes Ethernet, IP, TCP, and UDP packets in real-time, displaying relevant information such as MAC addresses, IP addresses, and port numbers.

## Features
- Captures packets from a specified network interface
- Extracts and displays Ethernet, IP, TCP, and UDP headers
- Filters packets based on protocol
- Supports real-time packet capture and analysis

## Prerequisites
- A Linux system with a working network interface (Tested on Debian in a Virtual Machine)
- `libpcap` installed

### Install `libpcap`
#### Debian/Ubuntu:
```bash
sudo apt install libpcap-dev

#### Fedora:
```bash
sudo dnf install libpcap-devel

##Setup & Usage
###Find Your Network Interface
Before running the program, check your network interface name:
```bash
ip link show
This will list all available network interfaces. Look for an interface name like enp0s3, eth0, or wlp2s0.

By default, it captures packets from enp0s3. If your interface is different, modify the source code:
```C
handle = pcap_open_live("your-interface", BUFSIZ, 1, 1000, errbuf);



###Compile the program
```bash
gcc sniffer.c -o sniffer -lpcap

###Run the packet sniffer
```bash
sudo ./sniffer
