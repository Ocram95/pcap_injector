# pcap_injector 

pcapStego is a simple CLI tool for creating IPv6 network covert channels within a .pcap file. The modified .pcap can be then used for simulations, create datasets or be lively replayed on a network via tools like [Tcpreplay](https://tcpreplay.appneta.com). 

# Background

A network covert channel is a hidden communication path laying within a network conversation (see, [here](https://github.com/cdpxe/Network-Covert-Channels-A-University-level-Course/blob/master/README.md) for a crash-course on network information hiding). pcapStego can be used to transmit an arbitrary string/content via a network covert channel targeting IPv6 traffic. Supported injections mechanisms allow to embed information in: 

- Flow Label
- Traffic Class
- Hop Limit

Even if network covert channels can be used for licit purposes, e.g., to enforce privacy and to protect sources in investigative journalism, they are mainly exploited by malware to conceal its presence. Specifically, covert channels are regularly used to exfiltrate data, orchestrate attacks, retrieve malicious payloads and support several steps of the cyber kill chain. To this aim, pcapStego comes with two "databases" of attacks that can be used to simulate the transfer of various malicious entities. Specifically:

- fileless.db: contains several samples of file-less malware that can be injected in the .pcap to simulate the transmission of a threat via a covert channel;

- payload.db. contains several samples of malicious payloads (both obfuscated and clean) that can be injected in the .pcap for simulating a multi-stage loading architecture.  

# Getting Started

## Basic Usage

```pcapStego --help```

prints the help.


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
