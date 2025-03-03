
- [1. Describe Common Network Application Attacks](#1-describe-common-network-application-attacks)
  - [1.1. Password Attacks](#11-password-attacks)
  - [1.2. DNS-Based Attacks](#12-dns-based-attacks)
  - [1.3. DNS Tunnelling](#13-dns-tunnelling)
  - [1.4. Web-Based Attacks](#14-web-based-attacks)
  - [1.5. HTTP 302 Cushioning](#15-http-302-cushioning)
  - [1.6. Command Injections](#16-command-injections)
  - [1.7. SQL-Site Scripting and Request Forgery](#17-sql-site-scripting-and-request-forgery)
  - [1.8. Cross-Site Scripting and Request Forgery](#18-cross-site-scripting-and-request-forgery)
  - [1.9. Email-Based Attacks](#19-email-based-attacks)


# 1. Describe Common Network Application Attacks

## 1.1. Password Attacks

    Some methods used to obtain passwords. 
    - Password guessing
    - Brute-force attacks
    - Dictionary Attacks
    - Phishing Attacks
    
    Some common password attack tools that are openly available include: Cain and Abel, John the Ripper, OphCrack, and L0phtCrack.

    A common approach to reducing the risk of password brute-force attacks is to lock the account or increase the delay between login attempts when there have been repeated failures. This can be effective in slowing down brute-force attacks and giving the incident response team time to react.

    Another countermeasure against password attacks is two-factor authentication.

## 1.2. DNS-Based Attacks

## 1.3. DNS Tunnelling

    DNS tunneling is where another protocol or data is hidden in the DNS packets. Typically, attackers will use DNS tunneling for stealthy data exfiltration in a data breach or for the CnC traffic communications.

    Two of the common encoding methods include Base32 and Base64 encoding:

    - Tunneling non-DNS data within DNS traffic abuses both the DNS protocol and its records. Every type of DNS record (for instance, NULL, TXT, SRV, MX, CNAME, or A) can be used, and the speed of the communications is determined by the amount of data that can be stored in a single record of each type. TXT records can store the most data and are typically used in DNS tunnel implementations. However, it is not as common to frequently request this type of DNS record, so it may be more easily detected
    - The outbound phase starts by splitting the desired data on the local host into many encoded data chunks. Each data chunk (for example, 10101) is placed in the third- or lower-level domain name label of a DNS query (for example, 10101.cnc.tld). There will be no cached response on the local or network DNS server for this query. Therefore, the query is forwarded to the ISP’s recursive DNS servers.
    - The recursive DNS service that is used by the network will then forward the query to the cybercriminal’s authoritative name server. This process is repeated using multiple DNS queries depending on the number of data chunks to send out.
    - The inbound phase is triggered when the cybercriminal’s authoritative name server receives DNS queries from the infected device. It may send responses for each DNS query, which encapsulates encoded commands. The malware on the infected device recombines these fragmented commands and executes them.
    - Alternatively, if two-way communication is not necessary, either the queries or responses can exclude the encapsulated data or commands, making it more inconspicuous to avoid detection.

    Countermeasures to attacks that are based on DNS tunneling include the following:
    - Monitor the DNS log for suspicious activities such as DNS queries with unusually long and suspicious domain names.
    - Deploy a solution such as Cisco Umbrella to block the DNS tunneling traffic from going out to the malicious domains.

## 1.4. Web-Based Attacks

    The figure shows how attackers use WordPress servers as their ransomware infrastructure.
![alt text](image.png)

    Countermeasures to web-based attacks include the following:
    - To help defend against today's web-based attacks, web application developers must follow best security practices in developing their web applications, for example, referencing the best practices recommended by Open Web Application Security Project (OWASP).
    - Keep the operating system and web browser versions up-to-date.
    - Deploy services such as Cisco Umbrella to block the users from accessing malicious websites.
    - Deploy a web proxy security solution, such as the Cisco Web Security Appliance, to block users from accessing malicious websites.
    - Educate end users on how web-based attacks occur.

## 1.5. HTTP 302 Cushioning

    A website can change the path that is used to reach a resource by issuing an HTTP redirect to direct the user's web browser to the new location. The 302 Found HTTP response status code can be used for this purpose. The HTTP response status code 302 Found is a common way of performing URL redirection. Attackers often use legitimate HTTP functions, such as HTTP redirects, to carry out their attacks. 

    An HTTP response with the 302 Found status code will also provide a URL in the location header field. The browser interprets the 302 HTTP response status code to mean that the requested resource has been temporarily relocated to the new location provided in the response. The browser is invited to make an identical request to the new URL that is specified in the location field. The HTTP/1.0 specification (RFC 1945) gives the 302 HTTP response status code the description "Moved Temporarily."

    The figure illustrates an example where an attacker has compromised a legitimate website (example.com), causing the website to respond to the victim's HTTP request to compromise.example.com/index.php with the 302 Found HTTP response status code. This creates a series of HTTP 302 redirects through the attacker's proxies before the victim's browser is finally redirected to the attacker's web page that spreads the malicious exploit to the victim.

    ![alt text](image-1.png)

    The figure shows a partial Wireshark output, which illustrates the HTTP 302 response where a compromised website is used to redirect the victim.
    ![alt text](image-2.png)

    Countermeasures to attacks using HTTP 302 cushioning include the following:
    - Use a service such as Cisco Umbrella to block the users from accessing malicious web sites.
    - Deploy a web proxy security solution, such as the Cisco Web Security Appliance (WSA) to block users from accessing malicious web sites.
    - Educate end users on how the browser is redirected to a malicious web page that delivers the exploit to the victim's machine through a series of HTTP 302 redirections.

## 1.6. Command Injections

    Command injection is an attack whereby an attacker's goal is to execute arbitrary commands on the web server's OS via a vulnerable web application. Command injection vulnerability occurs when the web application supplies vulnerable, unsafe input fields to the malicious users to input malicious data.

    The following example illustrates the use of command injection in an HTTP request:

    - When viewing a file in a web application, the file name is often shown in the URL. Normal URL:
        http://www.example.com/sensitive/cgi-bin/userData.pl?doc=user1.txt

    - The attacker modified the above URL with the command injection that will execute the /bin/ls command:
        http://www.example.com/sensitive/cgi-bin/userData.pl?doc=/bin/ls


## 1.7. SQL-Site Scripting and Request Forgery

    SQL attacks are very common because databases, which often contain sensitive and valuable information, are attractive targets.

    An SQL injection attack consists of inserting a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data, execute administration operations on the data

    The following is the same query with a SQL injection:
            SELECT UserID FROM users WHERE username = 'anything' OR 1=1 -- AND password = 'hacktheplanet'
    
    The result is that the query will succeed, even though it should have failed, given the invalid username and password. The problem is that the attacker will get logged in as the first user that matches, which is not a good thing because the first user in the database is generally an administrator. The attack could be modified to target a specific username, but the attacker would have to know (or guess) that username.

    Countermeasures include the following:
    - Application developers should follow the best practices to perform proper user input validation, constrain, and sanitize the user input data.
    - Deploy an IPS solution to detect and prevent malicious SQL injections.

## 1.8. Cross-Site Scripting and Request Forgery

    Both XSS and cross-site request forgery (CSRF) are prevalent threats to the security of web applications. Understanding how these web-based attacks work will help you investigate and prevent the attacks from spreading across the secured network.

    XSS is a type of command injection web-based attack, which uses malicious scripts that are injected into otherwise benign and trusted websites. The malicious scripts are then served to other victims who are visiting the infected websites. For example, the malicious script may steal all the sensitive data from the user's cookies that are stored in the browser.

    CSRF is a type of attack that occurs when a malicious website, email, blog, instant message, and so on causes a user's web browser to perform an unwanted action on a trusted website for which the user is currently authenticated. 

    You need to beware that XSS and CSRF can also be used in combination during attacks, for example the attacks can use XSS to automatically submit the CSRF HTTP request (so that victims do not have to click a link), but XSS or CSRF do not depend on each other.

    ### XSS 
    #### Types of XSS attacks include
    Stored (Persistent) 
        Stored XSS is the most damaging type because it is permanently stored in the XSS-infected server. The victim receives the malicious script from the server whenever they visit the infected web page.
    Reflected (non-persistent)
        Most Common type
        In order for the attack to succeed, the victim needs to click the infected link. Reflected XSS attacks are typically delivered to the victims via an email message or through some other website. 
    
    Countermeasures include the following:
    - Deploy a service such as Cisco Umbrella to block the users from accessing malicious websites.
    - Deploy a web proxy security solution, such as Cisco WSA, to block users from accessing malicious websites.
    - Deploy an IPS solution to detect and prevent malicious XSS or CSRF.
    - Educate end users—for example, how to recognize phishing attacks.

    ### Cross-Site Request Forgery

    CSRF attacks can include unauthorized changes of user information or the extraction of user-sensitive data from a web application. CSRF exploits utilize social engineering to convince a user to open a link that, when processed by the affected web application, could result in arbitrary code execution.
    CSRF attacks are used by an attacker to make a target system perform a function via the target's browser without their knowledge, at least until the unauthorized transaction has been committed. Examples of CSRF attacks are numerous but the most common involves bank account fund transfers

## 1.9. Email-Based Attacks

    The following are examples of email threats:
    - Attachment-based
      -  Specifically crafted attacks come in targeted messages that include such malicious attachments.
    - Email Spoofing
      - The creation of email messages with a forged sender address that is meant to fool the recipient into providing money or sensitive information.
    - Spam
      - Unsolicited email or "junk" mail that you receive in your inbox.
    - Open mail relay
      - A Simple Mail Transfer Protocol (SMTP) server that is configured to allow anyone—not just known corporate users—on the internet to send an email. 
    - Homoglyphs
      - Text characters that have shapes that are identical or similar to each other. With the advanced phishing attacks today, phishing emails may contain homoglyphs.

    Countermeasures include the following:
    - Deploy an email security appliance/proxy, such as the Cisco Email Security Appliance (ESA), to detect and block a wide variety of email threats, such as malware, spam, phishing attempts, and so on.
    - Educate end users—for example, how to recognize phishing attacks, and to never open any suspicious email attachment.

