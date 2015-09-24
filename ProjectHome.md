Rebind the LAN PC's http connection to the wizard of router
if the router can't connect to the internet.

The program would do the following:
1. Reply a fake DNS response by using DNS rebinding if the LAN PC did a DNS query..

2. Hijack the TCP connection if the LAN PC try to connect to the internet.

3. Drop the ICMP destination unreachable on router