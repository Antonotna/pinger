# pinger
Windows console ping based on winpcap library

General difference from standart windows ping:

- Support for changing of DSCP value in IP header
- Support for fastping

```
C:\>pinger
usage: pinger [-t] [-f] [-n num] [-l len] [-v TOS]
                 [-i interval] [-h TTL] [--sid sid] [--sn sn] [-w timeout] host

Options:
        -t              Infinite ping
        -f              DF Bit
        -n num          Packets count (default is 4)
        -l len          Size of the packet. 64 < [size] < 1500 (default is 100)
        -v TOS          TOS
        -i int          Interval(in ms) between recieve packet and send the next one
                                                                (Default is 1000ms)
        -h TTL          Time to live
        --sid SID               SID field of ICMP header (radnom by default)
        --sn SN                 start SN field of ICMP header (1 by default)
        -w timeout              Timeout in seconds. (Default is 4)
```
