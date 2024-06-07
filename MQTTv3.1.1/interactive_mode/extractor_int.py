import sys
import optparse
import subprocess
import pandas as pd
from scapy.contrib import mqtt
from scapy.contrib.mqtt import MQTTConnect, MQTTPublish
from scapy.utils import rdpcap
from scapy.utils import wrpcap
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from scapy.layers.inet import IP, TCP, UDP
import random
import base64

# Field and length of them supported
FIELD_LENGTH = {
    "KA": 16,
    "CID": 8,
    "PW": 8,
    "USR": 8,
    "AM": 8,
    "TN": 1
}


def process_command_line(argv):
    parser = optparse.OptionParser()
    parser.add_option('-r', '--pcap', help='Specify the pcap to parse.', action='store', type='string', dest='pcap')
    parser.add_option('-f', '--field', help='Specify the field to inspect', action='store', type='string', dest='field')
    parser.add_option('-p', '--packets', help='Specify the number of packets to extract.', action='store', default = 0, type='int', dest='packets')
    parser.add_option('-b', '--bits', help='Specify the number of bits to extract.', action='store', default = 0, type='int', dest='bits')
    parser.add_option('-i', '--image', help='Specify to extract an image.', action='store', default = 'n', type='string', dest='image')

    settings, args = parser.parse_args(argv)

    if not settings.pcap:
        raise ValueError("A pcap file must be specified.")
    if not settings.field:
        raise ValueError("A field must be specified.")
    if settings.field not in FIELD_LENGTH:
        raise ValueError("The specified field is incorrect or not supported.")
    if not settings.packets:
        raise ValueError("The number of packets to extract must be specified.")
    if settings.image != 'y' and settings.image != 'n':
        raise ValueError("The image flag can only support value 'y' or 'n'.")

    # Fields of the CONNECT control packets
    if settings.field == "KA" or settings.field == "CID" or settings.field == "PW" or settings.field == "USR":
        msg_type = 1
    # Fields of the PUBLISH control packets
    elif settings.field == "AM" or settings.field == "TN":
        msg_type = 3
    else:
        raise ValueError("The specified field is incorrect or not supported.")

    return settings, args, msg_type


def find_flows(pcap_to_read, number_packets, msg_type):
    # Creation of csv file where each line is composed of three-tuple src and dst for each packet
    print("Creating tmp files...")
    if msg_type == 1:  # For CONNECT control packets
        create_tmp_csv = (
                "tshark -r "
                + pcap_to_read
                + f" -c 800 -Y 'mqtt.msgtype == {msg_type}' -T fields -e ip.src -e ip.dst -e tcp.dstport "
                  f"-e ip.proto -E header=y -E separator=, > tmp.csv"
        )
    else:
        create_tmp_csv = (
                "tshark -r "
                + pcap_to_read
                + f" -c 800 -Y 'mqtt.msgtype == {msg_type}' -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport "
                  f"-e ip.proto -E header=y -E separator=, > tmp.csv"
        )
    process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
    process.wait()

    df = pd.read_csv('tmp.csv')

    delete_tmp_csv = "rm tmp.csv"
    process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
    process.wait()
    print("Deleting tmp files...")
    df.index.name = "INDEX"

    # Count of packets that compose each flow, grouping by src, dst, and port
    if msg_type == 1:  # For CONNECT control packets
        df_mqtt_flows = df.groupby(['ip.src', 'ip.dst', 'tcp.dstport']).size().to_frame('#mqtt_pkts').reset_index()
    else:
        df_mqtt_flows = df.groupby(['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport']).size().to_frame('#mqtt_pkts').reset_index()

    # Return flows which contain at least 'number_of_packets' packets
    df_final = df_mqtt_flows[df_mqtt_flows['#mqtt_pkts'] >= number_packets]

    return df_final


def extract_packets(pcap, source, destination, src_port, dst_port, protocol, targeted_field, number_of_packets):
    print("Reading input pcap. This might take a few minutes...")
    pkts = rdpcap(pcap)
    secret_index = 0
    secret_extracted = ''
    print("Extracting...")

    for pkt in pkts:
        if TCP in pkt:
            if mqtt.MQTT in pkt:
                mqtt_pkt = pkt[mqtt.MQTT]
                if MQTTConnect in mqtt_pkt:
                    if pkt[IP].src == source and pkt[IP].dst == destination and pkt[TCP].dport == dst_port:
                        if secret_index < number_of_packets:
                            if targeted_field == "KA":
                                secret_extracted += mqtt_pkt.klive
                            elif targeted_field == "CID":
                                secret_extracted += mqtt_pkt.clientId.decode('utf-8')
                            elif targeted_field == "PW":
                                secret_extracted += mqtt_pkt.password.decode('utf-8')
                            elif targeted_field == "USR":
                                secret_extracted += mqtt_pkt.username.decode('utf-8')
                            secret_index += 1
                if MQTTPublish in mqtt_pkt:
                    if pkt[IP].src == source and pkt[IP].dst == destination and pkt.sport == src_port and pkt.dport == dst_port:
                        if secret_index < number_of_packets:
                            if targeted_field == "AM":
                                secret_extracted += mqtt_pkt.value.decode('utf-8')
                            elif targeted_field == "TN":
                                topic_name = mqtt_pkt.topic.decode('utf-8')
                                first_char = topic_name[0]
                                if first_char.isupper():
                                    secret_extracted += '1'
                                else:
                                    secret_extracted += '0'
                            secret_index += 1
    # Creation of 8 bit chunks to correctly interpret characters
    secret_in_chunks = list((secret_extracted[0+i:8+i] for i in range(0, len(secret_extracted), 8)))
    secret_string = ''
    for i in range(len(secret_in_chunks)):
        secret_string += chr(int(secret_in_chunks[i], 2))
        secret_extracted = secret_string
    if targeted_field == "TN":
        secret_extracted = ''.join(secret_extracted[i] for i in range(len(secret_extracted)))
        # Creation of 8 bit chunks to correctly interpret characters
        secret_in_chunks = [secret_extracted[i:i+8] for i in range(0, len(secret_extracted), 8)]
        secret_extracted = ''.join(chr(int(chunk, 2)) for chunk in secret_in_chunks)
    print('-' * 25)
    print("PAYLOAD EXTRACTED")
    return secret_extracted


def extract_bits(pcap, source, destination, src_port, dst_port, protocol, targeted_field, number_of_bits):
    print("Reading input pcap. This might take a few minutes...")
    pkts = rdpcap(pcap)
    secret_index = 0
    secret_extracted = ''
    print("Extracting...")

    for pkt in pkts:
        if TCP in pkt:
            if mqtt.MQTT in pkt:
                mqtt_pkt = pkt[mqtt.MQTT]
                if MQTTConnect in mqtt_pkt:
                    if pkt[IP].src == source and pkt[IP].dst == destination and pkt[TCP].dport == dst_port:
                        if secret_index < number_of_bits:
                            if targeted_field == "KA":
                                secret_extracted += mqtt_pkt.klive.to_bytes(2, 'big').decode('utf-8')
                                secret_index += 16
                            elif targeted_field == "CID":
                                client_id = mqtt_pkt.clientId.decode('utf-8')
                                secret_extracted += client_id[0]
                                secret_index += 8
                            elif targeted_field == "PW":
                                password = mqtt_pkt.password.decode('utf-8')
                                secret_extracted += password[0]
                                secret_index += 8
                            elif targeted_field == "USR":
                                username = mqtt_pkt.username.decode('utf-8')
                                secret_extracted += username[0]
                                secret_index += 8
                if MQTTPublish in mqtt_pkt:
                    if pkt[IP].src == source and pkt[IP].dst == destination and pkt.sport == src_port and pkt.dport == dst_port:
                        if secret_index < number_of_bits:
                            if targeted_field == "AM":
                                am = mqtt_pkt.value.decode('utf-8')
                                secret_extracted += am[0]
                                secret_index += 8
                            elif targeted_field == "TN":
                                topic_name = mqtt_pkt.topic.decode('utf-8')
                                first_char = topic_name[0]
                                if first_char.isupper():
                                    secret_extracted += '1'
                                else:
                                    secret_extracted += '0'
                                secret_index += 1
    if targeted_field == "TN":
        # Creation of 8 bit chunks to correctly interpret characters
        secret_in_chunks = [secret_extracted[i:i+8] for i in range(0, len(secret_extracted), 8)]
        secret_string = ''.join([chr(int(chunk, 2)) for chunk in secret_in_chunks])
        secret_extracted = secret_string
    print('-' * 25)
    print("PAYLOAD EXTRACTED")
    return secret_extracted


def flow_selection(flows, number, msg_type):
    source = flows.loc[number]['ip.src']
    destination = flows.loc[number]['ip.dst']
    if msg_type == 1:  # For CONNECT control packets
        protocol = 6
        dst_port = flows.loc[number]['tcp.dstport']
        return source, destination, None, int(dst_port), protocol
    else:  # For PUBLISH control packets
        protocol = 6
        if 'tcp.srcport' in flows.columns:  # Check if 'tcp.srcport' column exists
            src_port = flows.loc[number]['tcp.srcport']
        else:
            src_port = None
        dst_port = flows.loc[number]['tcp.dstport']
        return source, destination, src_port, int(dst_port), protocol


settings, args, msg_type = process_command_line(sys.argv)
flows = find_flows(settings.pcap, settings.packets, msg_type)
if len(flows) > 0:
    print('-' * 25)
    print("CONVERSATIONS FOUND")
    print(flows.head(50))
    print("Only the first 50 conversations are shown (if present).")
    print('-' * 25)
    while True:
        operation = input("Choose the flow to inspect: ")
        if operation.strip().isdigit():
            what_flow = int(operation)
            if not what_flow in flows.index:
                print("Invalid flow index")
                continue
            else:
                source, destination, src_port, dst_port, protocol = flow_selection(flows, what_flow, msg_type)
                break
        else:
            print("This operation is not supported!")
    print('-' * 25)
    if msg_type == 1:  # For CONNECT control packets
        # Adjust the Wireshark filter for CONNECT packets without the constraint on the source port
        print("Wireshark filter: ip.src == " + str(source) + " and ip.dst == " + str(destination) + " and tcp.dstport == " + str(dst_port))
    else:
        # Use the original Wireshark filter for other types of packets
        print("Wireshark filter: ip.src == " + str(source) + " and ip.dst == " + str(destination) + " and tcp.srcport == " + str(src_port) + " and tcp.dstport == " + str(dst_port))

    if settings.bits != 0:
        payload = extract_bits(settings.pcap, source, destination, src_port, dst_port, protocol, settings.field, settings.bits)
    else:
        payload = extract_packets(settings.pcap, source, destination, src_port, dst_port, protocol, settings.field, settings.packets)
    if settings.image == 'n':
        print(payload)
    else:
        decodeit = open('extr_image.png', 'wb')
        decodeit.write(base64.b64decode((payload)))
        decodeit.close()
else:
    print("No conversations are found within this pcap!")