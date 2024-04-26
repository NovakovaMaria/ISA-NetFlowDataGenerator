# ISA-NetFlowDataGenerator
The aim of this project is to implement a NetFlow exporter that will create NetFlow records from captured network data in pcap format and send them to a collector.

The program supports the following syntax for execution:
```
./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
```
where
- ```-f <file>``` is the name of the analyzed file or STDIN,
- ```-c <netflow_collector:port>``` is the IP address or hostname of the NetFlow collector. Optionally, a UDP port can be specified (127.0.0.1:2055, if not specified),
- ```-a <active_timer>``` is the interval in seconds after which active records are exported to the collector (60, if not specified),
- ```-i <seconds>``` is the interval in seconds after which inactive records are exported to the collector (10, if not specified),
- ```-m <count>``` is the size of the flow-cache. When the maximum size is reached, the oldest record in the cache is exported to the collector (1024, if not specified).

All parameters are considered optional. If a parameter is not specified, a default value will be used instead.

Example of use:
```
./flow -f input.pcap -c 192.168.0.1:2055
```

Implementation:
- in C++, using the libpcap library.
