import optparse
import pandas as pd
from scapy.contrib import mqtt
from scapy.all import *
from scapy.layers.inet import IP
from scapy.contrib.mqtt import *
import csv


def process_command_line(argv):
    parser = optparse.OptionParser()
    parser.add_option('-r', '--pcap', help='Specify the pcap to inject.', action='store', type='string', dest='pcap')
    parser.add_option('-a', '--attack', help='Specify the attack (i.e., text file, string).', action='store', type='string', dest='attack')
    parser.add_option('-w', '--output', help='Specify the output pcap file.', default='output.pcap', action='store', type='string', dest='output')

    settings, args = parser.parse_args(argv)

    if not settings.pcap:
        raise ValueError("A pcap file must be specified.")
    if not settings.attack:
        raise ValueError("A set of attacks must be specified.")

    return settings, args


def read_attack(attack_to_read):
    print("Reading the attack...")
    list_of_attacks = []
    filepath = attack_to_read
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            field, separator, attack = line.strip().rpartition(", ")
            attack_in_bits = ''.join(format(ord(bit), '08b') for bit in attack)
            if field == 'KA':
                dim_field = 16
                msg_type = 1
            elif field == 'CID':
                dim_field = 8
                msg_type = 1
            elif field == 'PW':
                dim_field = 8
                msg_type = 1
            elif field == 'USR':
                dim_field = 8
                msg_type = 1
            elif field == 'AM':
                dim_field = 8
                msg_type = 3
            elif field == 'TN':
                dim_field = 1
                msg_type = 3
            attack_in_chunks = [attack_in_bits[i:i+dim_field] for i in range(0, len(attack_in_bits), dim_field)]
            list_of_attacks.append((field, attack_in_chunks, msg_type))
            line = fp.readline()
    return list_of_attacks


def find_flows(pcap_to_read, list_of_attacks):
    # Creation of csv file where each line is composed of three-tuple src and dst for each packet
    print("Creating tmp files...")
    create_tmp_csv = "tshark -r " + pcap_to_read + " -Y \"not icmp\" -c 800 -T fields -e mqtt.msgtype -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.proto -E header=y -E separator=, > tmp.csv"
    process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
    process.wait()

    # Count of packets that compose each flow, grouping by src, dst and fl
    df = pd.read_csv('tmp.csv')

    # Deleting of csv file
    delete_tmp_csv = "rm tmp.csv"
    process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
    process.wait()
    print("Deleting tmp files...")

    # Adding INDEX column name
    df.index.name = "INDEX"
    # Return flows which contains at least 'number_of_packets' packets
    df_final = df.groupby(['ip.src', 'ip.dst', 'ip.proto', 'tcp.srcport', 'tcp.dstport']).size().to_frame('#mqtt_pkts').reset_index()
    df_final = df_final.fillna('-')

    list_of_dict = []
    for attack in list_of_attacks:
        field, attack_in_chunks, msg_type = attack
        number_of_packets_needed = len(attack_in_chunks)
        found_flows = False
        for _, flow in df.iterrows():
            if flow['mqtt.msgtype'] == msg_type:
                if msg_type == 1:  # CONNECT Control packets
                    num_packets_in_flow = df[(df['ip.src'] == flow['ip.src']) &
                                             (df['ip.dst'] == flow['ip.dst']) &
                                             (df['ip.proto'] == flow['ip.proto']) &
                                             (df['tcp.dstport'] == flow['tcp.dstport'])].shape[0]
                else:
                    num_packets_in_flow = df[(df['ip.src'] == flow['ip.src']) &
                                             (df['ip.dst'] == flow['ip.dst']) &
                                             (df['ip.proto'] == flow['ip.proto']) &
                                             (df['tcp.srcport'] == flow['tcp.srcport']) &
                                             (df['tcp.dstport'] == flow['tcp.dstport'])].shape[0]

                if num_packets_in_flow >= number_of_packets_needed:
                    found_flows = True
                    list_of_dict.append(create_dict_attack(flow, attack, 'tcp'))
                    if msg_type == 1:  # CONNECT Control packets
                        df = df.drop(df[(df['ip.src'] == flow['ip.src']) &
                                        (df['ip.dst'] == flow['ip.dst']) &
                                        (df['ip.proto'] == flow['ip.proto']) &
                                        (df['tcp.dstport'] == flow['tcp.dstport'])].index)
                    elif msg_type == 3:
                        df = df.drop(df[(df['ip.src'] == flow['ip.src']) &
                                        (df['ip.dst'] == flow['ip.dst']) &
                                        (df['ip.proto'] == flow['ip.proto']) &
                                        (df['tcp.srcport'] == flow['tcp.srcport']) &
                                        (df['tcp.dstport'] == flow['tcp.dstport'])].index)
                    break
        if not found_flows:
            print("There are no flows with enough packets to contain attack for field:", field)

    return list_of_dict


def create_dict_attack(flow, attack, proto):
    tmp_dict = {'src': str(flow['ip.src']), 'dst': str(flow['ip.dst'])}
    if proto == 'tcp':
        tmp_dict['psrc'] = int(flow['tcp.srcport'])
        tmp_dict['pdst'] = int(flow['tcp.dstport'])
    tmp_dict['proto'] = int(flow['ip.proto'])
    tmp_dict['msg_type'] = int(flow['mqtt.msgtype'])
    tmp_dict['target_field'] = attack[0]
    tmp_dict['attack'] = attack[1]
    tmp_dict['counter'] = 0
    tmp_dict['counter_pub'] = 0
    tmp_dict['n-delay'] = 0
    return tmp_dict


# Capitalization pattern of the topic name based on the binary representation of the string to insert
def modify_topic(original_topic, attack_chunk):
    first_char = original_topic[0]
    attack_bit = attack_chunk[0]
    if attack_bit == '1':
        new_topic = first_char.upper() + original_topic[1:]
    else:
        new_topic = first_char.lower() + original_topic[1:]
    return new_topic


def inject(pcap, attack_dict):
    print("Reading input pcap. This might take a few minutes...")
    pkts = rdpcap(pcap, 1000)
    modified_pkts = []

    resulting_pcap_file = settings.output

    print("Injecting...")

    for pkt in pkts:
        if TCP in pkt:
            # Packet info
            p_source, p_destination, p_psrc, p_pdst, p_proto = pkt[IP].src, pkt[IP].dst, pkt.sport, pkt.dport, pkt[IP].proto
            if mqtt.MQTT in pkt:
                mqtt_pkt = pkt[mqtt.MQTT]
                for attack in attack_dict:
                    a_source, a_destination, a_psrc, a_pdst, a_proto = attack['src'], attack['dst'], attack['psrc'], attack['pdst'], attack['proto']
                    if MQTTConnect in mqtt_pkt:
                        if p_source == a_source and p_destination == a_destination and p_proto == a_proto and p_pdst == a_pdst:
                            # CONNECT Packet Handling
                            if attack['counter'] < len(attack['attack']):
                                targeted_field = attack['target_field']
                                if targeted_field == "KA":
                                    new_klive = int(attack['attack'][attack['counter']], 2)
                                    mqtt_pkt.klive = new_klive
                                elif targeted_field == "CID":
                                    new_clientId = ''.join(chr(int(attack['attack'][attack['counter']][i:i+8], 2)) for i in range(0, len(attack['attack'][attack['counter']]), 8))
                                    remaining_length = mqtt_pkt.clientIdlen - len(new_clientId)
                                    mqtt_pkt.clientId = new_clientId + mqtt_pkt.clientId[-remaining_length:].decode('utf-8')
                                elif targeted_field == "PW":
                                    if mqtt_pkt.passwordflag == 1:
                                        new_password = ''.join(chr(int(attack['attack'][attack['counter']][i:i+8], 2)) for i in range(0, len(attack['attack'][attack['counter']]), 8))
                                        remaining_length = mqtt_pkt.passlen - len(new_password)
                                        mqtt_pkt.password = new_password + mqtt_pkt.password[-remaining_length:].decode('utf-8')
                                    else:
                                        raise ValueError("This flow does not contain authenticated packets")
                                elif targeted_field == "USR":
                                    if mqtt_pkt.usernameflag == 1:
                                        new_username = ''.join(chr(int(attack['attack'][attack['counter']][i:i+8], 2)) for i in range(0, len(attack['attack'][attack['counter']]), 8))
                                        remaining_length = mqtt_pkt.userlen - len(new_username)
                                        mqtt_pkt.username = new_username + mqtt_pkt.username[-remaining_length:].decode('utf-8')
                                    else:
                                        raise ValueError("This flow does not contain authenticated packets")
                                attack['counter'] += 1

                    if MQTTPublish in mqtt_pkt:
                        targeted_field = attack['target_field']
                        if p_source == a_source and p_destination == a_destination and p_proto == a_proto and p_pdst == a_pdst and p_psrc == a_psrc:
                            # PUBLISH Packet Handling
                            if attack['counter_pub'] < len(attack['attack']):
                                if targeted_field == "AM":
                                    new_value = ''.join(chr(int(attack['attack'][attack['counter_pub']][i:i+8], 2)) for i in range(0, len(attack['attack'][attack['counter_pub']]), 8))
                                    remaining_length = len(mqtt_pkt.value) - len(new_value)
                                    mqtt_pkt.value = new_value + mqtt_pkt.value[-remaining_length:].decode('utf-8')
                                elif targeted_field == "TN":
                                    original_topic = mqtt_pkt.topic.decode('utf-8')
                                    new_topic = modify_topic(original_topic, attack['attack'][attack['counter_pub']])
                                    mqtt_pkt.topic = new_topic.encode('utf-8')
                                attack['counter_pub'] += 1
        # Checksum calculation
        if pkt.haslayer(IP):
            del pkt[IP].chksum
        modified_pkts.append(pkt)

    wrpcap(resulting_pcap_file, modified_pkts)

    print("Injection successfully finished!")
    return resulting_pcap_file


def write_wireshark_filters(attacks_and_flows):
    print("Wireshark filters:")
    for x in attacks_and_flows:
        if x['msg_type'] == 1: #CONNECT
            filter_str = f"ip.src == {x['src']} and ip.dst == {x['dst']} and tcp.dstport == {x['pdst']}"
        else:
            filter_str = f"ip.src == {x['src']} and ip.dst == {x['dst']} and tcp.srcport == {x['psrc']} and tcp.dstport == {x['pdst']}"
        print(filter_str)


def write_to_csv(csv_file_name, attacks_and_flows):
    csv_exists = os.path.isfile(csv_file_name)
    with open(csv_file_name, mode='a') as file:
        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        if not csv_exists:
            writer.writerow(['field', 'src', 'dst', 'p_src', 'p_dst', 'proto', 'length [packet]', 'length [bit]'])
        for x in attacks_and_flows:
            bit_length = 0
            for l in x['attack']:
                bit_length += len(l)
            writer.writerow([x['target_field'], x['src'], x['dst'], x['psrc'], x['pdst'], x['proto'], len(x['attack']), bit_length])


def reorder_timing_pcap_file(pcap_to_reorder):
    print("Reordering pcap file...")
    pcap_reordered = "reordered_" + str(pcap_to_reorder)
    reorder_pcap_file = "reordercap " + pcap_to_reorder + " " + pcap_reordered
    process = subprocess.Popen(reorder_pcap_file, shell=True, stdout=subprocess.PIPE)
    process.wait()
    delete_pcap_file = "rm " + pcap_to_reorder
    process = subprocess.Popen(delete_pcap_file, shell=True, stdout=subprocess.PIPE)
    process.wait()


settings, args = process_command_line(sys.argv)
list_of_attacks = read_attack(settings.attack)
attacks_and_flows = find_flows(settings.pcap, list_of_attacks)
resulting_pcap_file = inject(settings.pcap, attacks_and_flows)
reorder_timing_pcap_file(resulting_pcap_file)
write_to_csv('injected_flows.csv', attacks_and_flows)
write_wireshark_filters(attacks_and_flows)
