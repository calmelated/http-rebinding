# http-rebinding
This tool is used for a NAT(Network Address Translator) router 
to redirect the connections from its LAN(Local Area Network) to 
its management page.

Before a router connects to WAN(Wide Area Network), all connections 
from LAN will be rejected by the router. But this program will clone 
these the packets, and make redirect response to these clients, including 
DNS, UDP, and TCP. The redirect will make the connection be transfer to 
router's management page. Therefore, the users would know he/she needs to 
do some configurations in order to connect to WAN. 

### Setup
 - Make sure you have socket library in your Linux
 - `git clone` this project
 - `make` to comiple 
 - `./web-rebinding
 
 
