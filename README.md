# pcapStego

pcapStego is a simple CLI tool for creating network covert channels within a .pcap file. The modified .pcap can be then used for simulations, create datasets or be lively replayed on a network via tools like [Tcpreplay](https://tcpreplay.appneta.com). 
In general, there are two modes:
- interactive mode, which allows the user to manually establish the covert channel choosing the flow to inject, the secret and the injection mechanism.
- bulk mode, which enables the automatization of the entire process, combining multiple secrets and injection mechanisms at once.

Each mode consists of two Python scripts that allows the injection and the extraction processes.

Currently pcapStego supports the following protocols and covert channels:
- IPv4: Type of Service (8 bit/pkt), Time To Live (1 bit/pkt), Identification Number (16 bit/pkt), Timing (1 bit/pkt)
- IPv6: Flow Label (20 bit/pkt), Traffic Class (8 bit/pkt), Hop Limit (1 bit/pkt), Timing (1 bit/pkt)
- ICMPv4: Payload (48 bit/pkt), Timing (1 bit/pkt)
- ICMPv6: Payload (8 bit/pkt), Timing (8 bit/pkt)
- MQTTv3.1.1: Keep-Alive (16 bit/pkt), Client ID (8 bit/pkt), Password (8 bit/pkt), Username (8 bit/pkt), Application Message (8 bit/pkt), Topic Name (1 bit/pkt)

## Updates
- 07/06/24: MQTTv3.1. support for bulk mode. Covert channels: Keep-Alive, Client ID, Password, Username, Application Message, Topic Name
- 03/06/24: MQTTv3.1. support for interactive mode. Covert channels: Keep-Alive, Client ID, Password, Username, Application Message, Topic Name
- 03/02/22: ICMPv4/v6 support for interactive mode. Covert channels: Payload, Timing
- 10/09/21: IPv4 support for both interactive and bulk mode. Covert channels: Type of Service, Time To Live, Identification Number, Timing
- 07/09/21: first release, IPv6 support for both interactive and bulk mode. Covert channels: Flow Label, Traffic Class, Hop Limit, Timing

## Background

A network covert channel is a hidden communication path laying within a network conversation (see, [here](https://github.com/cdpxe/Network-Covert-Channels-A-University-level-Course/blob/master/README.md) for a crash-course on network information hiding). pcapStego can be used to transmit an arbitrary string/content via both storage and timing network covert channels. 

Even if network covert channels can be used for licit purposes, e.g., to enforce privacy and to protect sources in investigative journalism, they are mainly exploited by malware to conceal its presence. Specifically, covert channels are regularly used to exfiltrate data, orchestrate attacks, retrieve malicious payloads and support several steps of the cyber kill chain. To this aim, pcapStego comes with two "databases" of attacks that can be used to simulate the transfer of various malicious entities. Specifically:

- fileless.db: contains several samples of file-less malware that can be injected in the .pcap to simulate the transmission of a threat via a covert channel;

- payload.db. contains several samples of malicious payloads (both obfuscated and clean) that can be injected in the .pcap for simulating a multi-stage loading architecture.  

Commands and payloads are took from [FCL](https://github.com/chenerlich/FCL) repository.

## Dependencies
Two libraries are necessary to work with pcapStego.
- Scapy:
```pip3 install scapy```
- Pandas:
```pip3 install pandas```


# Basic Usage
Let's take a look at the parameters of the ```injector_int.py``` script for the interactive mode in the IPv6 folder: 
```
$ python3 injector_int.py [-h HELP] [-r PCAP] [-f FIELD] [-a ATTACK] [-w OUTPUT]
```
The three mandatory parameters represent: 
- ```-r PCAP``` it specifies the .pcap file to read and inject.
- ```-f FIELD``` it specifies the target field to exploit. The available fields are: Flow Label (FL), Traffic Class (TC), Hop Limit (HL), and TIMING.
- ```-a ATTACK``` it specifies the attack to inject. It can be either a txt file or a string.
- ```-w OUTPUT``` it specifies the output pcap file (optional, the default is "output.pcap").

Instead, its counterpart the ```extractor_int.py``` script: 
```
$ python3 extractor_int.py [-h HELP] [-r PCAP] [-f FIELD] [-p PACKETS] [-b BITS] [-i IMAGE]
```
The three mandatory parameters represent: 
- ```-r PCAP``` it specifies the .pcap file to read and parse.
- ```-f FIELD``` it specifies the target field to inspect. The available fields are: Flow Label (FL), Traffic Class (TC), Hop Limit (HL), and TIMING.
- ```-p PACKETS``` it specifies the number of packets to extract.
- ```-b BITS``` it specifies the number of bits to extract. It is strongly recommended in the case of the 20-bit Flow Label field, otherwise is optional.
- ```-i IMAGE``` it specifies whether to extract an image.

Similar commands are used for the bulk mode:  
```
$ python3 injector_bulk.py [-h HELP] [-r PCAP] [-a ATTACK] [-w OUTPUT] 
```
The two parameters represent: 
- ```-r PCAP``` it specifies the .pcap file to read and inject.
- ```-a ATTACK``` it specifies a .txt file containing multiple attacks. It is formatted in the following form: [FIELD], [ATTACK].
- ```-w OUTPUT``` it specifies the output pcap file (optional, the default is "output.pcap").

The extraction process takes advantage of the .csv generated by the injection:
```
$ python3 extractor_bulk.py [-h HELP] [-r PCAP] [-i INJECTED-CSV]
```
The two parameters represent: 
- ```-r PCAP``` it specifies the .pcap file to read and parse.
- ```-i INJECTED-CSV``` it specifies the .csv generated by the injection that contains all the information of the injected flows.

## Example Usages
```
$ python3 injector_int.py -r pcap_example.pcap -f TC -a hello_world.txt
```
This command will inject the payload contained in the "cmd.txt" into the Traffic Class field of a flow chosen by the user within the specified pcap.
Each attack is tracked in a csv file for future purposes.

```
$ python3 extractor_int.py -r TC_a=hello_world.txt_pcap_example.pcap -f TC -p 11
```
This command will extract the Traffic Class values of the first 11 packets of a flow chosen by the user within the specified pcap.

For bulk mode, instead: 
```
python3 injector_bulk.py -r pcap_example.pcap -a attacks.txt
python3 extractor_bulk.py -r attacks.txt_pcap_example.pcap -i injected_flows.csv
```
Similar commands can be used for the other protocols.

# References

* M. Zuppelli, L. Caviglione, [pcapStego: A Tool for Generating Traffic Traces for Experimenting with Network Covert Channels](https://dl.acm.org/doi/10.1145/3465481.3470067), in Proceedings of the 16th International Conference on Availability, Reliability and Security (ARES 2021), Article 95, pp. 1–8, Aug. 2021.

## Papers on Stegomalware

* K. Cabaj, L. Caviglione, W. Mazurczyk, S. Wendzel, A. Woodward, S. Zander, [The New Threats of Information Hiding: The Road Ahead](https://ieeexplore.ieee.org/abstract/document/8378979), IT Professional, Vol. 20, No. 3, pp. 31-39, May./Jun. 2018, doi: 10.1109/MITP.2018.032501746.

* W. Mazurczyk, L. Caviglione, [Information Hiding as a Challenge for Malware Detection](https://ieeexplore.ieee.org/document/7085644), IEEE Security & Privacy, Vol. 13, No. 2, pp. 89-93, Mar.-Apr. 2015, doi: 10.1109/MSP.2015.33.

## Paper on IPv6 Covert Channels

* W. Mazurczyk, K. Powójski, L. Caviglione, [IPv6 Covert Channels in the Wild](https://dl.acm.org/doi/10.1145/3360664.3360674), in Proceedings of the Third Central European Cybersecurity Conference (CECC 2019), Munich, Germany, pp. 1 - 6, Nov. 2019. 

## Others

* [Steg-in-the-wild](https://github.com/lucacav/steg-in-the-wild): a curated list of real-world threats, attacks and malware leveraging information hiding, covert channels and steganography.
* [Malware - Fileless Command Lines](https://github.com/chenerlich/FCL): a repository containing malicious command-lines and malware execution processes.
* [CAIDA IPv6 traffic traces](https://www.caida.org/data/passive/passive_dataset.xml): traffic dumps collected by CAIDA to conduct experiments.

# Acknowledgement 

This work has been supported by EU Project [SIMARGL](https://simargl.eu) - Secure Intelligent Methods for Advanced Recognition of Malware and Stegomalware, Grant Agreement No 833042.
