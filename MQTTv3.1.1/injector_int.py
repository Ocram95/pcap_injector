import optparse
import subprocess
import pandas as pd
from scapy.contrib import mqtt
from scapy.all import *
from scapy.layers.inet import IP
from scapy.contrib.mqtt import *
import random
import base64
import csv

#Field and length of them supported
FIELD_LENGTH = {
    "KA": 16,
    "CID": 184,
    "PW": 524280,
    "USR": 524280,
    "U-P": 1048560,
    "AM": 8,
    "TN": 1,
    "TIMING": 1
}


def process_command_line(argv):
    parser = optparse.OptionParser()
    parser.add_option('-r', '--pcap', help='Specify the pcap to inject.', action='store', type='string', dest='pcap')
    parser.add_option('-f', '--field', help='Specify the field to exploit to contain the payload (i.e., KA, CID, PW, '
                                            'USR, U-P, AM, TN, TIMING).',
                      action='store', type='string', dest='field')
    parser.add_option('-a', '--attack', help='Specify the attack (i.e., text file, string).', action='store',
                      type='string', dest='attack')
    parser.add_option('-w', '--output', help='Specify the output pcap file.', default='output.pcap', action='store',
                      type='string', dest='output')

    settings, args = parser.parse_args(argv)

    if not settings.pcap:
        raise ValueError("A pcap file must be specified.")
    if not settings.field:
        raise ValueError("A field must be specified.")
    if settings.field not in FIELD_LENGTH:
        raise ValueError("The specified field is incorrect or not supported.")
    if not settings.attack:
        raise ValueError("An attack must be specified.")

    return settings, args


def read_attack(attack_to_read, field):
    print("Reading the attack...")
    dim_field = FIELD_LENGTH[field]
    if attack_to_read.endswith('.txt'):
        file = open(attack_to_read, "r")
        file_in_string = file.read()
    elif attack_to_read.endswith('.jpg') or attack_to_read.endswith('.png'):
        with open(attack_to_read, "rb") as image2string:
            file_in_string = base64.b64encode(image2string.read()).decode("utf-8")
    else:
        file_in_string = str(attack_to_read)
    attack_in_bits = ''.join(format(ord(bit), '08b') for bit in file_in_string)
    # Division in chunks of 'dim_field' size
    attack_in_chunks = [attack_in_bits[i:i+dim_field] for i in range(0, len(attack_in_bits), dim_field)]
    # If TIMING I need at least one packet before the secret to understand if the secret
    # starts with 1 or 0
    if field == "TIMING":
        attack_in_bits_tmp = '0' + attack_in_bits
        attack_in_bits = attack_in_bits_tmp
        attack_in_chunks.insert(0, '0')
    print("Number of packets needed: " + str(len(attack_in_chunks)))
    print("Number of bits needed: " + str(len(attack_in_bits)))
    return attack_in_chunks, str(len(attack_in_chunks)), str(len(attack_in_bits))


def find_flows(pcap_to_read, number_packets, msg_type):
    # Creation of csv file where each line is composed of three-tuple src and dst for each packet
    print("Creating tmp files...")
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

    # Count of packets that compose each flow, grouping by src, dst and fl
    df_mqtt_flows = df.groupby(['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport']).size().to_frame('#mqtt_pkts').reset_index()

    # Return flows which contains at least 'number_of_packets' packets
    df_final = df_mqtt_flows[df_mqtt_flows['#mqtt_pkts'] >= number_packets]

    return df_final


# def pad(data):
#     return data + bytes([16 - len(data) % 16] * (16 - len(data) % 16))
#
#
# def encrypt_aes(key, data):
#     cipher = AES.new(key, AES.MODE_ECB)
#     padded_data = pad(data.encode())
#     ciphertext = cipher.encrypt(padded_data)
#     return base64.urlsafe_b64encode(ciphertext)


# Capitalization pattern of the topic name based on the binary representation of the string to insert
def modify_topic(original_topic, attack_chunk):
    first_char = original_topic[0]
    attack_bit = attack_chunk[0]
    if attack_bit == '1':
        new_topic = first_char.upper() + original_topic[1:]
    else:
        new_topic = first_char.lower() + original_topic[1:]
    return new_topic


def inject(pcap, source, destination, src_port, dst_port, protocol, targeted_field, attack_in_chunks):
    print("Reading input pcap. This might take a few minutes...")
    pkts = rdpcap(pcap, 800)
    modified_pkts = []
    wire_len = []
    secret_index_connect = 0
    secret_index_publish = 0
    resulting_pcap_file = settings.output

    # Delay and number of delays to add for timing CC
    delta = 10
    n = 0

    print("Injecting...")

    for pkt in pkts:
        if TCP in pkt:
            if mqtt.MQTT in pkt:
                mqtt_pkt = pkt[mqtt.MQTT]
                wire_len.append(pkt.wirelen)
                if MQTTConnect in mqtt_pkt:
                    # Search for the correct flow
                    if pkt[IP].src == source and pkt[IP].dst == destination and pkt.sport == src_port and pkt.dport == dst_port:
                        # If there is still something to inject
                        if secret_index_connect < len(attack_in_chunks):
                            if targeted_field == "KA":
                                new_klive = int(attack_in_chunks[secret_index_connect], 2)
                                mqtt_pkt.klive = new_klive
                            elif targeted_field == "CID":
                                new_clientId = ''.join(chr(int(attack_in_chunks[secret_index_connect ][i:i+8], 2)) for i in range(0, len(attack_in_chunks[secret_index_connect]), 8))
                                # encrypted_clientId = encrypt_aes(aes_key, new_clientId)
                                if mqtt_pkt.clientIdlen < len(new_clientId):
                                    mqtt_pkt.clientId = new_clientId[:mqtt_pkt.clientIdlen]
                                else:
                                    remaining_length = mqtt_pkt.clientIdlen - len(new_clientId)
                                    mqtt_pkt.clientId = new_clientId + mqtt_pkt.clientId[-remaining_length:].decode('utf-8')
                            elif targeted_field == "PW":
                                if mqtt_pkt.passwordflag == 1:
                                    new_password = ''.join(chr(int(attack_in_chunks[secret_index_connect][i:i+8], 2)) for i in range(0, len(attack_in_chunks[secret_index_connect]), 8))
                                    if mqtt_pkt.passlen < len(new_password):
                                        mqtt_pkt.password = new_password[:mqtt_pkt.passlen]
                                    else:
                                        remaining_length = mqtt_pkt.passlen - len(new_password)
                                        mqtt_pkt.password = new_password + mqtt_pkt.password[-remaining_length:].decode('utf-8')
                                else:
                                    raise ValueError("This flow does not contain authenticated packets")
                            elif targeted_field == "USR":
                                if mqtt_pkt.usernameflag == 1:
                                    new_username = ''.join(chr(int(attack_in_chunks[secret_index_connect][i:i+8], 2)) for i in range(0, len(attack_in_chunks[secret_index_connect]), 8))
                                    if mqtt_pkt.userlen < len(new_username):
                                        mqtt_pkt.username = new_username[:mqtt_pkt.userlen]
                                    else:
                                        remaining_length = mqtt_pkt.userlen - len(new_username)
                                        mqtt_pkt.username = new_username + mqtt_pkt.username[-remaining_length:].decode('utf-8')
                                else:
                                    raise ValueError("This flow does not contain authenticated packets")
                            elif targeted_field == "U-P":
                                if mqtt_pkt.usernameflag == 1:
                                    new_username = ''.join(chr(int(attack_in_chunks[secret_index_connect][i:i+8], 2)) for i in range(0, len(attack_in_chunks[secret_index_connect]), 8))
                                    if mqtt_pkt.passwordflag == 1:
                                        if len(new_username.encode('utf-8')) > mqtt_pkt.userlen:
                                            excess_len = len(new_username.encode('utf-8')) - mqtt_pkt.userlen
                                            new_username = new_username[:-excess_len]
                                            new_password = attack_in_chunks[secret_index_connect][-(excess_len*8):]
                                        else:
                                            new_password = ''
                                        mqtt_pkt.username = new_username
                                        mqtt_pkt.password = ''.join(chr(int(new_password[i:i+8], 2)) for i in range(0, len(new_password), 8))
                                        if mqtt_pkt.passlen < len(mqtt_pkt.password):
                                            mqtt_pkt.password = mqtt_pkt.password[:mqtt_pkt.passlen]
                                    else:
                                        raise ValueError("This flow does not contain authenticated packets")
                                else:
                                    raise ValueError("This flow does not contain authenticated packets")
                            secret_index_connect += 1

                if MQTTPublish in mqtt_pkt:
                    if pkt[IP].src == source and pkt[IP].dst == destination and pkt.sport == src_port and pkt.dport == dst_port:
                        if secret_index_publish < len(attack_in_chunks):
                            if targeted_field == "AM":
                                am_len = mqtt_pkt.underlayer.len - mqtt_pkt.length - 2
                                new_value = ''.join(chr(int(attack_in_chunks[secret_index_publish][i:i+8], 2)) for i in range(0, len(attack_in_chunks[secret_index_publish]), 8))
                                if am_len >= len(new_value):
                                    mqtt_pkt.value = new_value
                                else:
                                    mqtt_pkt.value = new_value[:am_len]
                            elif targeted_field == "TN":
                                original_topic = mqtt_pkt.topic.decode('utf-8')
                                new_topic = modify_topic(original_topic, attack_in_chunks[secret_index_publish])
                                mqtt_pkt.topic = new_topic.encode('utf-8')
                            elif targeted_field == "TIMING":
                                if int(attack_in_chunks[secret_index_publish], 2) == 1:
                                    n += 1
                            secret_index_publish += 1
                    # Modify the time of each packet. In case of non-timing CCs, n = 0 and nothing happens. Otherwise,
                    # the time change according to n and delta.
                    pkt.time += n * delta
        # Checksum calculation
        if pkt.haslayer(IP):
            del pkt[IP].chksum
        modified_pkts.append(pkt)

    wrpcap(resulting_pcap_file, modified_pkts)

    print("Injection successfully finished!")
    return resulting_pcap_file


def reorder_timing_pcap_file(pcap_to_reorder):
    print("Reordering pcap file...")
    pcap_reordered = "reordered_" + str(pcap_to_reorder)
    reorder_pcap_file = "reordercap " + pcap_to_reorder + " " + pcap_reordered
    process = subprocess.Popen(reorder_pcap_file, shell=True, stdout=subprocess.PIPE)
    process.wait()
    delete_pcap_file = "rm " + pcap_to_reorder
    process = subprocess.Popen(delete_pcap_file, shell=True, stdout=subprocess.PIPE)
    process.wait()


def flow_selection(flows, number):
    source = flows.loc[number]['ip.src']
    destination = flows.loc[number]['ip.dst']
    if not flows.loc[number]['tcp.srcport'] == '-':
        protocol = 6
        src_port = flows.loc[number]['tcp.srcport']
        dst_port = flows.loc[number]['tcp.dstport']
    elif not flows.loc[number]['udp.srcport'] == '-':
        protocol = 17
        src_port = flows.loc[number]['udp.srcport']
        dst_port = flows.loc[number]['udp.dstport']
    else:
        raise ValueError("Flow protocol not supported or recognized.")

    if protocol == 6:
        return source, destination, int(src_port), int(dst_port), protocol
    else:
        raise ValueError("Flow protocol not supported or recognized.")


def write_to_csv(csv_file_name, filename, attack, field, src, dst, p_src, p_dst, proto, lengthb, lengthp):
    csv_exists = os.path.isfile(csv_file_name)
    with open(csv_file_name, mode='a') as file:
        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        if not csv_exists:
            writer.writerow(['file name', 'attack', 'field', 'src', 'dst', 'p_src', 'p_dst', 'proto', 'length [packet]', 'length [bit]'])

        writer.writerow([filename, attack, field, src, dst, p_src, p_dst, proto, lengthb, lengthp])


settings, args = process_command_line(sys.argv)
attack_in_chunks, lengthp, lengthb = read_attack(settings.attack, settings.field)

# Fields of the CONNECT control packets
if settings.field == "KA" or settings.field == "CID" or settings.field == "PW" or settings.field == "USR" or settings.field == "U-P":
    msg_type = 1
# Fields of the PUBLISH control packets
elif settings.field == "AM" or settings.field == "TN" or settings.field == "TIMING":
    msg_type = 3
else:
    raise ValueError("The specified field is incorrect or not supported.")

flows = find_flows(settings.pcap, len(attack_in_chunks), msg_type)
if len(flows) > 0:
    print('-' * 25)
    print("CONVERSATIONS FOUND")
    print(flows.head(50))
    print("Only the first 50 conversations are shown (if present).")
    print('-' * 25)
    while True:
        operation = input("Choose the flow by its index (leave it blank for the first flow or 'r' for a random choice): ")
        if operation.strip().isdigit():
            what_flow = int(operation)
            if not what_flow in flows.index:
                print("Invalid flow index")
                continue
            else:
                source, destination, src_port, dst_port, protocol = flow_selection(flows, what_flow)
                break
        elif operation == 'r':
            rnd_flow = random.choice(flows.index.tolist())
            print('Flow ' + str(rnd_flow) + ' is chosen.')
            source, destination, src_port, dst_port, protocol = flow_selection(flows, rnd_flow)
            break
        elif operation == '':
            print('First flow is chosen.')
            first_flow = flows.index.tolist()[0]
            source, destination, src_port, dst_port, protocol = flow_selection(flows, first_flow)
            break
        else:
            print("This operation is not supported!")
    print('-' * 25)
    print("Wireshark filter: ip.src == " + str(source) + " and ip.dst == " + str(destination) + " and tcp.srcport == " + str(src_port) + " and tcp.dstport == " + str(dst_port))
    resulting_pcap_file = inject(settings.pcap, source, destination, src_port, dst_port, protocol, settings.field, attack_in_chunks)
    write_to_csv('injected_flows.csv', settings.pcap, settings.attack, settings.field, source, destination, src_port, dst_port, protocol, lengthp, lengthb)
    if settings.field == "TIMING":
        reorder_timing_pcap_file(resulting_pcap_file)
else:
    print("No conversations with enough packets are found in this pcap!")



