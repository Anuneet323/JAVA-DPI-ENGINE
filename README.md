# Java Deep Packet Inspection (DPI) Engine

## Project Summary

A high-performance, multi-threaded Deep Packet Inspection (DPI) engine
built in Java that processes raw PCAP network traffic, performs
protocol-level parsing, extracts application-layer intelligence, and
applies rule-based traffic filtering.

This project demonstrates strong expertise in networking fundamentals,
systems programming, concurrency, and low-level protocol handling.

------------------------------------------------------------------------

## Why This Project Matters

Modern firewalls and intrusion detection systems analyze traffic beyond
basic IP filtering.\
This DPI engine simulates core components of such systems by:

-   Inspecting packets across multiple OSI layers
-   Identifying applications using TLS SNI and HTTP headers
-   Tracking bidirectional flows using Five-Tuple
-   Applying domain-based and application-based filtering rules
-   Supporting concurrent packet processing

------------------------------------------------------------------------

## Core Capabilities

### Packet Processing

-   Custom PCAP reader with endian detection
-   Manual parsing of Ethernet, IPv4, TCP, and UDP headers
-   Zero-copy payload handling for efficiency

### Application Identification

-   TLS ClientHello parsing to extract SNI
-   HTTP Host header extraction
-   DNS traffic detection via protocol + port inspection

### Flow Management

-   Five-Tuple (src IP, dst IP, src port, dst port, protocol) flow
    tracking
-   Thread-safe flow storage using ConcurrentHashMap
-   Stateful traffic classification

### Rule Engine

-   Application blocking (e.g., YouTube)
-   Domain-based filtering (e.g., facebook.com)
-   Real-time drop/forward decision logic

### Multi-Threaded Architecture

-   Producer--consumer model
-   BlockingQueue-based packet dispatch
-   Fixed worker thread pool
-   Atomic statistics counters

### Output Support

-   Wireshark-compatible PCAP writer
-   Traffic logging for blocked packets

------------------------------------------------------------------------

## System Architecture

PCAP Input\
↓\
Packet Parser (L2 → L3 → L4)\
↓\
Flow Tracker (Five-Tuple Based State)\
↓\
Application Detection (DNS / HTTP / HTTPS via SNI)\
↓\
Rule Engine (Block / Allow Decision)\
↓\
Statistics + Optional PCAP Output

------------------------------------------------------------------------

## Technical Strengths Demonstrated

-   Binary-level protocol parsing
-   TLS handshake structure analysis
-   Thread-safe concurrent design
-   Memory-efficient packet handling
-   Corruption-safe PCAP parsing
-   Clean modular project structure

------------------------------------------------------------------------

## Project Structure

java-dpi-engine
│
├── README.md                 # Project documentation
├── .gitignore                # Ignore compiled & IDE files
│
└── src
    │
    ├── main                  # Entry points
    │   ├── MainSingle.java   # Single-thread DPI execution
    │   └── MainMulti.java    # Multi-thread DPI execution
    │
    ├── engine                # Core DPI logic
    │   ├── DpiEngine.java
    │   ├── FastPath.java
    │   ├── Flow.java
    │   ├── FlowTracker.java
    │   ├── RuleManager.java
    │   └── Statistics.java
    │
    ├── parser                # Protocol parsing & extraction
    │   ├── PacketParser.java
    │   ├── SNIExtractor.java
    │   ├── HTTPExtractor.java
    │   └── DNSDetector.java
    │
    ├── model                 # Data models
    │   ├── Packet.java
    │   ├── FiveTuple.java
    │   └── AppType.java
    │
    └── pcap                  # PCAP handling
        ├── PcapReader.java
        ├── PcapWriter.java
        └── PcapGlobalHeader.java

------------------------------------------------------------------------

## How to Compile

From project root:

    javac -d out (Get-ChildItem -Recurse -Path src -Filter *.java | ForEach-Object {$_.FullName})

------------------------------------------------------------------------

## How to Run

Single-thread version:

    java -cp out main.MainSingle test_dpi.pcap

Multi-thread version:

    java -cp out main.MainMulti test_dpi.pcap

------------------------------------------------------------------------

## Future Enhancements

-   TCP stream reassembly
-   IPv6 support
-   PCAP-NG compatibility
-   Performance benchmarking (packets/sec metrics)
-   Intrusion detection signatures
-   Real-time packet capture integration

------------------------------------------------------------------------

## Author

Name- Anuneet Singh Chauhan 
Systems & Networking Project -- Java
