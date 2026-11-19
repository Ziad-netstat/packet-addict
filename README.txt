==============================================================================
 PACKET ADDICT
 Packet sniffer + port scanner in one command-line tool
==============================================================================

Packet Addict is a small Python tool for learning how networks behave. It can
watch live network traffic (sniffer) and check which ports are open on a
host (port scanner). It was built and tested on Kali Linux.

  - Sniffer : captures packets live and shows TCP, UDP, ICMP, ARP and DNS
              activity, then prints a summary when you stop it.
  - Scanner : checks which TCP ports are open on a target and reads the
              banner (the greeting) each service sends back.


------------------------------------------------------------------------------
 FEATURES
------------------------------------------------------------------------------

  * Live capture that runs until you press Ctrl+C (or stop after N packets)
  * Per-packet lines for TCP (with flags), UDP, ICMP, ARP and DNS queries
  * End-of-capture summary: protocol counts, top talkers, most-targeted ports
  * Simple port-scan detection (flags IPs that send many bare SYN packets)
  * Optional BPF filters, for example: "tcp port 80" or "host 192.168.1.5"
  * Save captures to a .pcap file you can open in Wireshark
  * Fast multi-threaded TCP port scanner with service names and banners
  * Lists your network interfaces so you know which one to sniff on


------------------------------------------------------------------------------
 REQUIREMENTS
------------------------------------------------------------------------------

  * Python 3.8 or newer
  * Scapy 2.5 or newer (listed in requirements.txt)
  * Root privileges (sudo) for sniffing. Scanning does not need root.
  * Linux is recommended (tested on Kali Linux). macOS also works with sudo.
    On Windows, sniffing needs Npcap installed; the scanner works as is.


------------------------------------------------------------------------------
 INSTALLATION
------------------------------------------------------------------------------

1) Download the project

     git clone https://github.com/Ziad-netstat/packet-addict
     cd packet-addict

   (Or click "Code" > "Download ZIP" on GitHub, unzip it, and open a
   terminal inside the folder.)

2) Install the requirements. Pick ONE of the options below.

   Option A - Kali / Debian / Ubuntu (simplest):

     sudo apt install python3-scapy

   Option B - Virtual environment (works anywhere, avoids system conflicts):

     python3 -m venv venv
     source venv/bin/activate
     pip install -r requirements.txt

   If you use Option B, run the sniffer with the virtual environment's
   Python so that sudo can find Scapy:

     sudo ./venv/bin/python3 packet_addict.py sniff -i eth0

   Note: on newer Kali/Debian systems, running "pip install" outside a
   virtual environment may fail with "externally-managed-environment".
   Use Option A or Option B to avoid that.

3) Check that it works

     python3 packet_addict.py

   You should see the Packet Addict banner and a list of commands.


------------------------------------------------------------------------------
 QUICK START
------------------------------------------------------------------------------

  1. List your network interfaces:

       python3 packet_addict.py interfaces

  2. Sniff traffic (press Ctrl+C to stop and see the summary):

       sudo python3 packet_addict.py sniff -i eth0

  3. Scan a host for open ports:

       python3 packet_addict.py scan 192.168.1.1


------------------------------------------------------------------------------
 COMMAND REFERENCE
------------------------------------------------------------------------------

General form:

  python3 packet_addict.py <command> [options]

Commands:  interfaces | sniff | scan
Running with no command shows the help screen.

--- interfaces ---------------------------------------------------------------

  python3 packet_addict.py interfaces

  Lists the network interfaces on your machine and their IP addresses. Use
  one of the names with the sniff command (-i).

--- sniff --------------------------------------------------------------------

  sudo python3 packet_addict.py sniff [-i INTERFACE] [-f FILTER]
                                      [-c COUNT] [-w FILE]

  Option              Meaning
  ------------------  ------------------------------------------------------
  -i, --interface     Interface to listen on, e.g. eth0, wlan0, lo.
                      If omitted, the default interface is used.
  -f, --filter        BPF filter, e.g. "tcp port 80", "udp port 53",
                      "icmp", "host 192.168.1.5".
  -c, --count         Stop after this many packets. Default: keep capturing
                      until you press Ctrl+C.
  -w, --write         Save the capture to a .pcap file (open in Wireshark).
                      Packets are written to disk as they arrive, so long
                      captures do not use up your RAM.

  Examples:

    sudo python3 packet_addict.py sniff -i eth0
    sudo python3 packet_addict.py sniff -i eth0 -c 50
    sudo python3 packet_addict.py sniff -i wlan0 -f "tcp port 443"
    sudo python3 packet_addict.py sniff -i eth0 -w capture.pcap
    sudo python3 packet_addict.py sniff -i lo -f "tcp"

  To stop a capture at any time, press Ctrl+C. The summary is printed, and
  the .pcap file (if you used -w) is saved.

--- scan ---------------------------------------------------------------------

  python3 packet_addict.py scan TARGET [-p PORTS] [-t THREADS]
                                       [--timeout SECONDS]

  Option              Meaning
  ------------------  ------------------------------------------------------
  TARGET              IP address or hostname to scan (required).
  -p, --ports         Ports to scan. Default: 1-1024.
                      Formats: "80"  |  "22,80,443"  |  "1-1024"
  -t, --threads       How many ports to check at the same time. Default: 100.
  --timeout           Seconds to wait for each port. Default: 1.0.
                      Increase it for slow or distant hosts.

  Examples:

    python3 packet_addict.py scan 192.168.1.1
    python3 packet_addict.py scan 192.168.1.1 -p 22,80,443
    python3 packet_addict.py scan 192.168.1.1 -p 1-65535 -t 200
    python3 packet_addict.py scan scanme.nmap.org -p 1-1024 --timeout 2


------------------------------------------------------------------------------
 EXAMPLE OUTPUT (sample, your results will differ)
------------------------------------------------------------------------------

Scan:

  [*] Scanning 192.168.1.1 (192.168.1.1) - 1024 ports, 100 threads

  PORT    SERVICE       BANNER
  22      ssh           SSH-2.0-OpenSSH_9.6p1 Debian
  80      http          HTTP/1.1 200 OK

  [+] 2 open port(s) found in 3.4s

Sniff:

  03:28:41 TCP   192.168.1.10:51234 -> 93.184.216.34:443 [S] len=74
  03:28:41 UDP   192.168.1.10:48211 -> 192.168.1.1:53 len=72 DNS query: example.com.
  03:28:42 ICMP  192.168.1.10 -> 192.168.1.1 type=8


------------------------------------------------------------------------------
 HOW TO READ THE RESULTS
------------------------------------------------------------------------------

Scan results
  Each row is an OPEN port, with the service normally used on that port and
  the banner the service sent back (often its software name and version).
  Ports that are not listed were closed, or blocked by a firewall.

TCP flags (shown in square brackets while sniffing)
  S   SYN      "I want to connect"
  SA  SYN-ACK  "OK, I accept"
  A   ACK      acknowledgment
  PA  PSH-ACK  packet carrying data
  F   FIN      "I'm done, closing the connection"
  R   RST      connection rejected or aborted

  A normal connection starts with S, then SA, then A (the "three-way
  handshake").

Possible port scan warning
  If one IP sends 20 or more bare SYN packets during a capture, the summary
  flags it as a possible port scan.


------------------------------------------------------------------------------
 TROUBLESHOOTING
------------------------------------------------------------------------------

"error: the following arguments are required: cmd"
  You ran the tool without a command. Add one: interfaces, sniff or scan.

"Need root to sniff. Run with sudo."
  Sniffing needs elevated privileges. Put sudo before the command.

"ModuleNotFoundError: No module named 'scapy'"
  Scapy is not installed. See INSTALLATION. If you used a virtual
  environment, run the tool with sudo ./venv/bin/python3 ...

"externally-managed-environment" when running pip install
  Use "sudo apt install python3-scapy" or a virtual environment.

Sniffer shows no packets
  You may be on the wrong interface. Run the interfaces command and try
  another one. To watch traffic to/from your own machine (127.0.0.1) you
  must use "-i lo".

Scan finds nothing
  The host may be offline or protected by a firewall. Try increasing
  --timeout, and confirm the host is reachable first (for example with
  "ping").


------------------------------------------------------------------------------
 LIMITATIONS
------------------------------------------------------------------------------

  * The scanner uses full TCP connections (TCP connect scan) and only scans
    TCP ports. It does not scan UDP.
  * Closed ports and filtered (firewalled) ports are both reported as "not
    open".
  * Scan results are printed when the scan finishes, not live.
  * Some IPv6-only traffic (such as ICMPv6) is counted as "OTHER".


------------------------------------------------------------------------------
 LEGAL DISCLAIMER
------------------------------------------------------------------------------

This tool is for education and authorized security testing only.

  * Only capture traffic on networks you own or have permission to monitor.
  * Only scan hosts you own or have explicit written permission to test.
  * Unauthorized sniffing or scanning may be illegal in your country.

The author is not responsible for misuse of this software. You are
responsible for how you use it.

A safe, legal target for practice: scanme.nmap.org (provided for testing).


------------------------------------------------------------------------------
 PROJECT FILES
------------------------------------------------------------------------------

  packet_addict.py   the tool
  requirements.txt   Python dependencies
  README.txt         this file


------------------------------------------------------------------------------
 AUTHOR / LICENSE
------------------------------------------------------------------------------

Author:  Ziad-netstat
License: MIT (see the LICENSE file)
