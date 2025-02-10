* Name:TEJASHRI SOMNATH MANDLIK.
* Company:CodeAlpha
* Domain:Cyber Security Internship
* Duration:2 month.
* Founder : Swati Srivastava.

# Overview of the Project
# Project: Basic Network Sniffer in python .

### **Overview of a Basic Network Sniffer in Python**

A **network sniffer** is a tool that monitors and captures network traffic (packets) traveling over a computer network. It is often used for network diagnostics, security monitoring, and analyzing network performance. A basic network sniffer in Python can capture packets, analyze their contents, and extract useful information such as source/destination IPs, protocols, and port numbers.

In Python, a network sniffer can be created using libraries like **Scapy**, which provides an easy-to-use interface to interact with network packets.

### **Key Concepts and Workflow of a Basic Network Sniffer**

1. **Packet Sniffing**: The process of capturing data packets from the network. These packets may contain various types of data, such as HTTP requests, TCP/UDP data, or ICMP messages.

2. **Packet Inspection**: Once a packet is captured, the sniffer inspects its contents, looking for specific fields such as:
   - **Source and Destination IP**: Identifying the origin and destination of the packet.
   - **Protocol**: The type of communication, such as TCP, UDP, ICMP, etc.
   - **Port Numbers**: The source and destination ports for protocols like TCP and UDP.

3. **Data Display**: After capturing and inspecting the packets, the sniffer typically displays the relevant information in an easy-to-read format. In a basic sniffer, you might see details like source IP, destination IP, and protocol type.

4. **Packet Filtering**: A network sniffer can be configured to capture only certain types of packets, such as TCP packets, UDP packets, or even packets from specific IP addresses.

### **Basic Network Sniffer Using Python**

Here's a breakdown of how a basic sniffer works using **Python** and the **Scapy** library.

#### **1. Importing Necessary Libraries**

Scapy is a Python library used to manipulate network packets. You can install it using `pip install scapy` if it’s not already installed.

```python
from scapy.all import sniff
```

#### **2. Defining a Callback Function**

The callback function is called for every packet that the sniffer captures. It processes the packet, extracting useful information.

```python
def packet_callback(packet):
    if packet.haslayer("IP"):  # Check if the packet has an IP layer
        ip_src = packet["IP"].src  # Extract source IP
        ip_dst = packet["IP"].dst  # Extract destination IP
        protocol = packet["IP"].proto  # Extract protocol type (TCP, UDP, etc.)
        
        # Print captured packet details
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol}")
        
        # Optionally, identify the type of protocol (TCP, UDP, ICMP)
        if packet.haslayer("TCP"):
            print("TCP Protocol detected.")
        elif packet.haslayer("UDP"):
            print("UDP Protocol detected.")
        elif packet.haslayer("ICMP"):
            print("ICMP Protocol detected.")
```

#### **3. Sniffing Packets**

The `sniff()` function from Scapy is used to capture packets. The parameters allow you to filter specific traffic, set a capture limit, and define the callback function that processes the packets.

```python
def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0, filter="ip", count=100)
```

- `prn=packet_callback`: Specifies the function to call for each captured packet.
- `store=0`: Prevents storing packets in memory, which is more efficient.
- `filter="ip"`: Captures only IP packets (you can change this to capture TCP/UDP/ICMP specifically).
- `count=100`: Captures up to 100 packets (you can remove `count` to run indefinitely).

#### **4. Running the Sniffer**

The following line starts the sniffer and begins capturing packets based on the criteria defined earlier.

```python
start_sniffing()
```

---

### **Key Features of a Basic Network Sniffer**

1. **Packet Capture**:
   - Captures all types of packets in real-time.
   - Can filter based on protocols (TCP, UDP, ICMP, etc.).

2. **Packet Inspection**:
   - Extracts information such as source IP, destination IP, and protocol from each packet.
   - Provides a basic analysis of each packet, helping to understand the traffic flow.

3. **Protocol Detection**:
   - Identifies the type of protocol (e.g., TCP, UDP, ICMP).
   - Useful for network analysis and security monitoring.

4. **Displaying Information**:
   - Outputs information about captured packets in an easy-to-read format.
   - Can display source and destination IP addresses and protocol type for each packet.

---

### **Use Cases of a Network Sniffer**

1. **Network Troubleshooting**:
   - Helps identify issues like packet loss, latency, or misconfigurations.
   - Diagnoses problems with network services and application connectivity.

2. **Security Monitoring**:
   - Monitors for suspicious activity, such as unauthorized IP addresses or protocols.
   - Helps detect potential security threats like ARP poisoning or packet injection.

3. **Traffic Analysis**:
   - Allows administrators to monitor network traffic for performance optimization.
   - Helps in understanding bandwidth usage patterns, application performance, and detecting anomalies.

---

### **Limitations of a Basic Network Sniffer**

1. **Limited to Network Access**:
   - A sniffer can only capture packets on the network it has access to. To monitor other networks, it would need to be positioned at key points in the network (e.g., a gateway or a router).

2. **Requires Proper Permissions**:
   - Capturing packets typically requires **root/administrator** privileges, as raw packet capture is a privileged operation.

3. **Basic Analysis**:
   - A basic sniffer only provides surface-level information (IP, protocol, etc.). For deeper analysis, additional layers of inspection, such as TCP flags, application-level data, or deeper security checks, would be required.

---

### **Extending the Basic Network Sniffer**

1. **Packet Logging**:
   - The sniffer can log captured packets to a file (e.g., in `.pcap` format) for later analysis, using tools like Wireshark.

2. **Real-Time Alerts**:
   - The sniffer can be extended to send real-time alerts if suspicious traffic is detected (e.g., too many SYN packets indicating a potential SYN flood attack).

3. **Advanced Filters**:
   - You can customize the filter to capture packets only from specific IP addresses, specific ports, or even based on packet content.

4. **Graphical Interface**:
   - A more advanced version could have a GUI for displaying captured packets and analysis in real-time.


