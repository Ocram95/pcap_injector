# pcapSteg

pcapStego is a simple CLI tool for creating IPv6 network covert channels within a .pcap file. The modified .pcap can be then used for simulations, create datasets or be lively replayed on a network via tools like [Tcpreplay](https://tcpreplay.appneta.com). 

It consists of two Python scripts: the ```injector.py```, which allows the injection of a payload in a given field of a flow, and the ```extractor.py```, which is able to extract the payload from a given field of a flow.

# Background

A network covert channel is a hidden communication path laying within a network conversation (see, [here](https://github.com/cdpxe/Network-Covert-Channels-A-University-level-Course/blob/master/README.md) for a crash-course on network information hiding). pcapStego can be used to transmit an arbitrary string/content via a network covert channel targeting IPv6 traffic. Supported injections mechanisms allow to embed information in: 

- Flow Label (20 bit/packet)
- Traffic Class (8 bit/packet)
- Hop Limit (1 bit/packet)

Even if network covert channels can be used for licit purposes, e.g., to enforce privacy and to protect sources in investigative journalism, they are mainly exploited by malware to conceal its presence. Specifically, covert channels are regularly used to exfiltrate data, orchestrate attacks, retrieve malicious payloads and support several steps of the cyber kill chain. To this aim, pcapStego comes with two "databases" of attacks that can be used to simulate the transfer of various malicious entities. Specifically:

- fileless.db: contains several samples of file-less malware that can be injected in the .pcap to simulate the transmission of a threat via a covert channel;

- payload.db. contains several samples of malicious payloads (both obfuscated and clean) that can be injected in the .pcap for simulating a multi-stage loading architecture.  

# Dependencies
Two libraries are necessary to work with pcapSteg.
- Scapy:
```pip3 install scapy```
- Pandas:
```pip3 install pandas```


# Basic Usage
Let's take a look at the parameters of the ```injector.py``` tool: 
```
$ python3 injector.py [-h HELP] [-r PCAP] [-f FIELD] [-a ATTACK] 
```
The three mandatory parameters represent: 
- ```-r PCAP``` it specifies the .pcap file to read and inject.
- ```-f FIELD``` it specifies the target field to exploit. The available fields are: Flow Label (FL), Traffic Class (TC) and Hop Limit (HL).
- ```-a ATTACK``` it specifies the attack to inject. It can be either a txt file or a string.

Instead, the ```extractor.py``` tool: 
```
$ python3 extractor.py [-h HELP] [-r PCAP] [-f FIELD] [-a ATTACK] 
```
The three mandatory parameters represent: 
- ```-r PCAP``` it specifies the .pcap file to read and parse.
- ```-f FIELD``` it specifies the target field to inspect. The available fields are: Flow Label (FL), Traffic Class (TC) and Hop Limit (HL).
- ```-p PACKETS``` it specifies the number of packets to extract.

## Example Usages
```
$ python3 injector.py -r pcap_example.pcap -f TC -a cmd.txt
```
This command will inject the payload contained in the "cmd.txt" into the Traffic Class field of a flow chosen by the user within the specified pcap.

```
$ python3 extractor.py -r TC_injected_pcap_example.pcap -f TC -p 195
```
This command will extract the Traffic Class valuee of the first 195 packets of a flow chosen by the user within the specified pcap

# Further Reading

## Papers on Stegomalware

* K. Cabaj, L. Caviglione, W. Mazurczyk, S. Wendzel, A. Woodward, S. Zander, [The New Threats of Information Hiding: The Road Ahead](https://ieeexplore.ieee.org/abstract/document/8378979), IT Professional, Vol. 20, No. 3, pp. 31-39, May./Jun. 2018, doi: 10.1109/MITP.2018.032501746.

* W. Mazurczyk, L. Caviglione, [Information Hiding as a Challenge for Malware Detection](https://ieeexplore.ieee.org/document/7085644), IEEE Security & Privacy, Vol. 13, No. 2, pp. 89-93, Mar.-Apr. 2015, doi: 10.1109/MSP.2015.33.

## Paper on IPv6 Covert Channels

* W. Mazurczyk, K. Powójski, L. Caviglione, [IPv6 Covert Channels in the Wild](https://dl.acm.org/doi/10.1145/3360664.3360674), in Proceedings of the Third Central European Cybersecurity Conference (CECC 2019), Munich, Germany, pp. 1 - 6, Nov. 2019. 

## Tools, Curated Lists and Attacks

* [Steg-in-the-wild](https://github.com/lucacav/steg-in-the-wild): a curated list of real-world threats, attacks and malware leveraging information hiding, covert channels and steganography.

# Acknowledgement 

This work has been supported by EU Project [SIMARGL](https://simargl.eu) - Secure Intelligent Methods for Advanced Recognition of Malware and Stegomalware, Grant Agreement No 833042.
