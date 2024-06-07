import optparse
from scapy.contrib import mqtt
from scapy.contrib.mqtt import MQTTConnect, MQTTPublish
from scapy.all import *
from scapy.layers.inet import IP, TCP
import csv


def process_command_line(argv):
    parser = optparse.OptionParser()
    parser.add_option('-r', '--pcap', help='Specify the pcap to read.', action='store', type='string', dest='pcap')
    parser.add_option('-i', '--injected_flows', help='Specify csv file of the injected flows.', action='store', type='string', dest='injected_flows')

    settings, args = parser.parse_args(argv)

    if not settings.pcap:
        raise ValueError("A pcap file must be specified.")
    if not settings.injected_flows:
        raise ValueError("A csv file with the injected flows must be specified.")

    return settings, args


def create_dict_attack(injected_flows):
    list_of_dict = []
    with open(injected_flows) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        # Skip header
        next(csv_reader, None)
        for row in csv_reader:
            tmp_dict = {'target_field': row[0], 'src': row[1], 'dst': row[2], 'psrc': int(row[3]), 'pdst': int(row[4]),
                        'proto': int(row[5]), 'plenght': int(row[6]), 'blength': int(row[7]), 'counter': 0,
                        'counter_pub': 0, 'extracted': '', 'prev_time_packet': 0}
            list_of_dict.append(tmp_dict)

    return list_of_dict


def extract(pcap, attack_dict):
    print("Reading input pcap. This might takes few minutes...")
    pkts = rdpcap(pcap, 900)
    delta = 10
    print("Extracting...")

    for pkt in pkts:
        if TCP in pkt:
            # Packet info
            p_source, p_destination, p_psrc, p_pdst, p_proto = pkt[IP].src, pkt[IP].dst, pkt.sport, pkt.dport, pkt[IP].proto
            if mqtt.MQTT in pkt:
                mqtt_pkt = pkt[mqtt.MQTT]
                for attack in attack_dict:
                    a_source, a_destination, a_psrc, a_pdst, a_proto = attack['src'], attack['dst'], attack['psrc'], attack['pdst'], attack['proto']

                    if p_source == a_source and p_destination == a_destination and p_proto == a_proto:
                        if MQTTConnect in mqtt_pkt and p_pdst == a_pdst:
                            # CONNECT Packet Handling
                            if attack['counter'] < attack['blength']:
                                targeted_field = attack['target_field']
                                if targeted_field == "KA":
                                    attack['extracted'] += mqtt_pkt.klive.to_bytes(2, 'big').decode('utf-8')
                                    attack['counter'] += 16
                                elif targeted_field == "CID":
                                    clientId = mqtt_pkt.clientId.decode('utf-8')
                                    attack['extracted'] += clientId[0]
                                    attack['counter'] += 8
                                elif targeted_field == "PW":
                                    password = mqtt_pkt.password.decode('utf-8')
                                    attack['extracted'] += password[0]
                                    attack['counter'] += 8
                                elif targeted_field == "USR":
                                    username = mqtt_pkt.username.decode('utf-8')
                                    attack['extracted'] += username[0]
                                    attack['counter'] += 8

                        if MQTTPublish in mqtt_pkt and p_psrc == a_psrc and p_pdst == a_pdst:
                            # PUBLISH Packet Handling
                            if attack['counter_pub'] < attack['blength']:
                                targeted_field = attack['target_field']
                                if targeted_field == "AM":
                                    am = mqtt_pkt.value.decode('utf-8')
                                    attack['extracted'] += am[0]
                                    attack['counter_pub'] += 8
                                elif targeted_field == "TN":
                                    topic_name = mqtt_pkt.topic.decode('utf-8')
                                    first_char = topic_name[0]
                                    if first_char.isupper():
                                        attack['extracted'] += '1'
                                    else:
                                        attack['extracted'] += '0'
                                attack['counter_pub'] += 1

    extracted_attacks_in_chunks = []
    for attack in attack_dict:
        if attack['target_field'] == "TN":
            extracted_attacks_in_chunks.append((attack['target_field'],list((attack['extracted'][0+i:8+i] for i in range(0, len(attack['extracted']), 8)))))
        else:
            extracted_attacks_in_chunks.append((attack['target_field'], attack['extracted']))
    extracted_attacks = []
    for attack in extracted_attacks_in_chunks:
        secret_string = ''
        if attack[0] == "TN":
            for chunk in attack[1]:
                secret_string += chr(int(chunk, 2))
            extracted_attacks.append((attack[0], secret_string))
        else:
            secret_string += attack[1]
            extracted_attacks.append((attack[0], secret_string))
    return extracted_attacks


def write_extracted(attacks):
    print("Writing extracted payloads...")
    file = open("extracted_attacks.txt", "w")
    for x in attacks:
        file.write(x[0] + ', ' + x[1] + '\n')


settings, args = process_command_line(sys.argv)
attack_dict = create_dict_attack(settings.injected_flows)
attacks = extract(settings.pcap, attack_dict)
write_extracted(attacks)






















