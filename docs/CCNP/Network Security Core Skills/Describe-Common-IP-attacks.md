# 1 - Describe Common TCP/IP Attacks

## Contents


- [1 - Describe Common TCP/IP Attacks](#1---describe-common-tcpip-attacks)
  - [Contents](#contents)
  - [\[↑\] (#contents) Legacy TCP/IP Vulnerabilities](#-contents-legacy-tcpip-vulnerabilities)



## [] (#contents) Legacy TCP/IP Vulnerabilities
    Early tools were insecure as default. 
        E.g. rlogin, rcp, rsh - No password needed. 
    1988 "Morris worm", precuror to other well known attacks. Exploited common utilities `sendmail` and `finger` 
        Prompted changes ot rsh as it was core to both. 
    "Which four options are considered as the main protocols of the IP suite? (Choose four.)"
        - UDP, TCP, IP, ICMP
    Vulnerability types
        - Man-in-the-middle attach (MITM) 
          - Intercepts communication between two systems. Packets can be modified 
          - Can defeat authenticaiton mechanisims as the attacker waits till it's established before perfroming any actions. 
          - A form of MITM is called "eavesdropping." Eavesdropping differs only in that the perpetrator just copies IP packets off the network without modifying them in any way.
        - Session hijacking
          - Session hijacking is a twist on the MITM attack. The attacker gains physical access to the network, initiates a MITM attack, and then hijacks that session. In this manner, an attacker can illicitly gain full access to a destination computer by assuming the identity of a legitimate user.
        - IP address spoofing
          - Attackers spoof the source IP address in an IP packet. Can be used blind (Dos attacks) or non-blind (sequence-number oprediction, session hacking, firewall state inspection)
        - DoS attack
          - used to prevent legitimate users from accessing a system. 
        - Distributed Denial of Service (DDoS) attack
          -  A DDoS attack is a DoS attack that features a simultaneous, coordinated attack from multiple source machines.
        - Resource exhaustion attacks
          - Resource exhaustion attacks are forms of DoS attacks.
    ICMP Vulnerabilities
        `ping`, `traceroute` etc. 
       - Reconnaissance and scanning
         - ICMP unreachables: 
           - ICMP Protocol Unreachable tells an attacker that a protocol is not in use on the target device.
         - ICMP mask reply
           - tell a requesting endpoint what the correct subnet mask is for a given network.
         - ICMP redirects
           - An attacker can use this feature to send an ICMP redirect message to the victim's host, luring the victim's host into sending all traffic through a router that is owned by the attacker. ICMP redirect attack is an example of a MITM attack
         - ICMP router discovery
           - An attacker can perform a MITM attack using IRDP. Attackers can also spoof the IRDP messages to add bad route entries into a victim's routing table so that the victim's host will forward the packets to the wrong address and be unable to reach other networks, resulting in the form of a DoS attack.
         - Firewalk
           - Firewalking is an active reconnaissance technique that employs `traceroute` like techniques to analyze IP packet responses to determine the gateway access list filters and map out the networks. The firewalking technique works by sending out TCP or UDP packets with a TTL that is one greater than the targeted gateway. 
       - ICMP tunneling
         - An ICMP tunnel, that establishes a furtive connection between two remote computers using ICMP echo requests and reply packets. ICMP tunneling can be used to bypass firewalls rules through obfuscation of the actual traffic inside the ICMP packets.
       - ICMP-based operating system fingerprinting
         - Operating system fingerprinting is the process of learning which operating system is running on a device. ICMP can be used to perform an active operating system fingerprint scan. For example, if the ICMP reply contains a TTL value of 128, it is probably a Windows machine, and if the ICMP reply contains a TTL value of 64, it is probably a Linux-based machine.
       - Denial of service attacks
         - ICMP flood attack
           - The attacker overwhelms the targeted resource with ICMP echo request packets with the aim to slowdown the target machine. 
         - Smurf attack
           - Attacker broadcasts many ICMP echo request packets using a spoofed source IP (The actual target) 
    UDP Vulnerabilities
        UCP = Connectionless
        Most attacks involving UDP relate to exhaustion of some shared resource (buffers, link capacity, and so on), or exploitation of bugs in protocol implementations, causing system crashes or other insecure behavior.
    Attack Surface and Attack Vectors (https://ondemandelearning.cisco.com/apollo-alpha/sec-scor-12tcpipattack-20/pages/6)
        Attack surface = is the total sum of all the vulnerabilities in a given computing device or network that are accessible to the attackers.
        Attack vectors = the paths or means by which the attackers gain access to a resource (such as end-user hosts or servers) to deliver malicious software or malicious outcome.
        Attack Surfaces
          - The network attack surface 
            - Comprises all vulnerabilities that are related to ports, protocols, channels, devices (smartphones, laptops, routers, and firewalls), services, network applications, and even firmware interfaces.
          - The software attack surface
            - The complete profile of all functions in any code that is running in a given system that is available to an unauthenticated user. An attacker or a piece of malware can use various exploits to gain access and run code on the target machine. The software attack surface is calculated across many different kinds of code, including applications, email services, configurations, compliance policy, databases, executables, dynamic link libraries (DLLs), web pages, mobile apps, device OS, and so on.
          - The physical attack surface is composed of the security vulnerabilities in a given system that are available to an attacker in the same location as the target. The physical attack surface is exploitable through inside threats such as rogue employees, social engineering ploys, and intruders who are posing as service workers.
          - The social engineering attack surface usually takes advantage of human psychology: the desire for something free, the susceptibility to distraction, or the desire to be liked or to be helpful.
        An attack vector is a path or route by which an attack was carried out
          - Reconaissance Attacks
            - Packet sniffers
            - Ping Sweeps
            - Port Scans
            - Information Queries
            - Passive
              - User Groups
              - Website details
              - Shodan
            - Active
              - Port Scans
              - DNS lookups
              - Ping sweeps
              - Traceroute
              - OS Fingerprinting
          - Known Vulnerabilities
          - SQL Injection
          - Phishing
          - Malware
          - Weak Authentication
            - Passwowrd Attack
            - Spoofing/Masquerading
            - Session hijacking
            - Malware
          - Actor-In-The-Middle attacks
            - Physical Layer
              - Tap someones physical connection
            - Data Link Layer
              - Use ARP poisoning to redirect packets
                - ARP-based MITM attack is achieved when an attacker poisons the ARP cache of two devices with the MAC address of the attacker's network interface controller (NIC). When the ARP caches have been successfully poisoned, each victim device sends all its packets to the attacker when communicating to the other device and puts the attacker in the middle of the communications path between the two victim devices. 
            - Network Layer
              - Manipulate routing
                -  An ICMP MITM attack is accomplished by spoofing an ICMP redirect message to any router that is in the path between the victim client and server. An ICMP redirect message is typically used to notify routers of a better route; however, it can be abused to effectively route the victim's traffic through an attacker-controlled router. 
            - Sesssion Layer 
              - SSL/TLS AITM de-crypts and inspection. 
              - DNS spoofing is a MITM technique that is used to supply false DNS information to a host so that when they attempt to browse
              - Similar to the DNS attack, DHCP server queries and responses are intercepted.
            - Applicaiton Layer
              - Malware infrection and manipulates web pages. 
          DoS attacks
            - Reflection and Amplification Attacks
          Spoofing Attacks
            - IP Address spoofing
            - MAC adress spoofing
            - Application or service spoofing. 
              - E.g. DHCP spoofing
                - The attacker runs DHCP server software and replies to DHCP requests from legitimate clients. As a rogue DHCP server, the attacker can cause a DoS by providing invalid IP information. The attacker can also perform confidentiality or integrity breaches via a man-in-the-middle attack. The attacker can assign itself as the default gateway or DNS server in the DHCP replies, later intercepting IP communications from the configured hosts to the rest of the network.
              - DHCP Starvation
                - The attack eshausts the DHCP address pool. 