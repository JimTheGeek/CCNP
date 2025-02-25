# 1 - Describe Common TCP/IP Attacks

## Contents
 - [Legacy TCP/IP Vulnerabilities]



## [↑] (#contents) Legacy TCP/IP Vulnerabilities
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
          - The physical attack surface
            - 