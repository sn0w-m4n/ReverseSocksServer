# ReverseSocksServer

SocksServer is a reverse socks5 proxy for infiltration.

## Description:


### Usage:


HostA : A host can be accessed by the Internet with public IP address 6.7.8.9

HostB : Behind the firewall and cannot be accessed by the Internet


#### 1. Run the following command in HostA works as relay

``` 
python3 sockserver.py -r -p proxy_port -l relay_port 
```

#### 2. Run the following command in HostB works as reverse socks

```
python3 sockserver.py -s -h 6.7.8.9 -p relay_port
```

Now you can access the Intranet of HostB via socks5 address 6.7.8.9:proxy_port
