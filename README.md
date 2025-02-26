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
