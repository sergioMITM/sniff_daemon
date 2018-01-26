# sniff_daemon
python code for sniffing credentials form a MITM position - optimized for proxy server

this code is adapted from net-creds.py, refactored and stripped down to only grab http credentials
https://github.com/DanMcInerney/net-creds/blob/master/net-creds.py

# demo
demo is available at my [blog](https://sergiomitm.com/latest-credentials)

# usage
```
usage: sniff_daemon.py [-h] [-i INTERFACE] [-p PCAP] [-f PROXY_IP]
                       [-x PROXY_PORT]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Choose an interface
  -p PCAP, --pcap PCAP  Parse info from a pcap file; -p <pcapfilename>
  -f PROXY_IP, --proxy_ip PROXY_IP
                        This is the address of the proxy server; -f
                        192.168.0.4
  -x PROXY_PORT, --proxy_port PROXY_PORT
                        This is the port of the proxy server; -p 8080
```
