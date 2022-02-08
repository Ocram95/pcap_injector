import sys
import optparse
import subprocess
import pandas as pd
from scapy.utils import rdpcap
from scapy.utils import wrpcap
from scapy.all import *
from scapy.layers.inet6 import IPv6
import random
import base64
import csv

#Field and length of them supported
FIELD_LENGTH = {
	"FL": 20,
	"TC": 8,
	"HL": 1,
	"TIMING": 1
}

def process_command_line(argv):
	parser = optparse.OptionParser()
	parser.add_option('-r', '--pcap', help='Specify the pcap to inject.', action='store', type='string',dest='pcap')
	parser.add_option('-f', '--field', help='Specify the field to exploit to contain the payload (i.e., FL, TC, HL, TIMING).', action='store', type='string', dest='field')
	parser.add_option('-a', '--attack', help='Specify the attack (i.e., text file, string).', action='store', type='string', dest='attack')
	parser.add_option('-w', '--output', help='Specify the output pcap file.', default='output.pcap', action='store', type='string', dest='output')

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
	#Division in chunks of 'dim_field' size
	attack_in_chunks = [attack_in_bits[i:i+dim_field] for i in range(0, len(attack_in_bits), dim_field)]
	
	#If TIMING i need at least one packet before the secret to understand if the secret
	#starts with 1 or 0
	if field == "TIMING":
		attack_in_bits_tmp = '0' + attack_in_bits
		attack_in_bits = attack_in_bits_tmp
		attack_in_chunks.insert(0, '0')

	print("Number of packets needed: " + str(len(attack_in_chunks)))
	print("Number of bits needed: " + str(len(attack_in_bits)))
	return attack_in_chunks, str(len(attack_in_chunks)), str(len(attack_in_bits))

def find_flows(pcap_to_read, number_packets):
	#Creation of csv file where each line is composed of three-tuple src and dst for each packet 
	print("Creating tmp files...")
	create_tmp_csv = "tshark -r " + pcap_to_read + " -T fields -e ipv6.flow -e ipv6.src -e ipv6.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ipv6.nxt -E header=y -E separator=, > tmp.csv"
	process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	#Count of packets that compose each flow, grouping by src, dst and fl
	df = pd.read_csv('tmp.csv')
	df_tcp = df.groupby(['ipv6.flow', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'ipv6.nxt']).size().to_frame('#pkts').reset_index()
	df_udp = df.groupby(['ipv6.flow', 'ipv6.src', 'ipv6.dst', 'udp.srcport', 'udp.dstport', 'ipv6.nxt']).size().to_frame('#pkts').reset_index()
	#Deleting of csv file
	delete_tmp_csv = "rm tmp.csv"
	process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	print("Deleting tmp files...")
	#Adding INDEX column name
	df.index.name = "INDEX"
	#Return flows which contains at leats 'number_of_packets' packets
	df_final = df_tcp.append(df_udp, ignore_index=True)
	df_final = df_final[['ipv6.flow', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'ipv6.nxt', '#pkts']]
	df_final = df_final.fillna('-')
	return df_final.loc[df_final['#pkts'] >= number_packets]

def inject(pcap, source, destination, flow_label, src_port, dst_port, protocol, targeted_field, attack_in_chunks):
	print("Reading input pcap. This might take few minutes...")
	pkts = rdpcap(pcap)
	secret_index = 0
	wire_len = []
	index = 0
	#Delay and number of delays to add for timing CC
	delta = 1
	n = 0

	resulting_pcap_file = settings.output

	time_first_packet = 0
	start_time_cc = 0
	finish_time_cc = 0
	print("Injecting...")
	for x in range(len(pkts)):
		if time_first_packet == 0:
			time_first_packet = pkts[x].time 
		wire_len.append(pkts[x].wirelen)
		if TCP in pkts[x] or UDP in pkts[x]:
			#Search for the correct flow
			if source == pkts[x][IPv6].src and destination == pkts[x][IPv6].dst and flow_label == pkts[x][IPv6].fl and src_port == pkts[x].sport and dst_port == pkts[x].dport and protocol == pkts[x].nh:
				#If there is still something to inject
				if secret_index < len(attack_in_chunks):
					if secret_index == 0:
						start_time_cc = pkts[x].time - time_first_packet
					if targeted_field == "FL":
						pkts[x][IPv6].fl = int(attack_in_chunks[secret_index],2)
					elif targeted_field == "TC":
						pkts[x][IPv6].tc = int(attack_in_chunks[secret_index],2)
					elif targeted_field == "HL":
						if int(attack_in_chunks[secret_index],2) == 0:
							pkts[x][IPv6].hlim = 10
						else:
							pkts[x][IPv6].hlim = 250
					elif targeted_field == "TIMING":
						if int(attack_in_chunks[secret_index], 2) == 1:
							n += 1
					secret_index += 1
				if secret_index == len(attack_in_chunks) and finish_time_cc == 0:
					finish_time_cc = pkts[x].time - time_first_packet
				#Modify the time of each packet. In case of non-timing CCs, n = 0 and nothing happens. Otherwise, 
				#the time change according to n and delta.
				pkts[x].time += n * delta
			#Modify the time of packets in the opposite direction. This is necessary for timing CCs to respect the order
			#of received packet.
			# if source == pkts[x][IPv6].dst and destination == pkts[x][IPv6].src and flow_label == pkts[x][IPv6].fl and src_port == pkts[x].dport and dst_port == pkts[x].sport and protocol == pkts[x].nh:
			# 	pkts[x].time += n * delta	
		pkts[x].wirelen = wire_len[index]
		index += 1
		#WARNING: check if the linktype is what is needed
		wrpcap(resulting_pcap_file, pkts[x], append=True, linktype=101)
	print("CC starting: " + str(start_time_cc))
	print("CC finishing: " + str(finish_time_cc))
	print("Injection succesfully finished!")
	return resulting_pcap_file

def flow_selection(flows, number):
	source = flows.loc[number]['ipv6.src']
	destination = flows.loc[number]['ipv6.dst']
	flow_label_extended = flows.loc[number]['ipv6.flow']					#0x000f92c1
	flow_label = int(flow_label_extended[:2] + flow_label_extended[5:], 16)	#0xf92c1 -> 1020609
	if not flows.loc[number]['tcp.srcport'] == '-':
		protocol = 6
		src_port = flows.loc[number]['tcp.srcport']
		dst_port = flows.loc[number]['tcp.dstport']
	elif not flows.loc[number]['udp.srcport'] == '-':
		protocol = 17
		src_port = flows.loc[number]['udp.srcport']
		dst_port = flows.loc[number]['udp.dstport']
	return source, destination, flow_label, int(src_port), int(dst_port), protocol

def write_to_csv(csv_file_name, filename, attack, field, src, dst, p_src, p_dst, proto, lengthb, lengthp):
	csv_exists = os.path.isfile(csv_file_name)
	with open(csv_file_name, mode='a') as file:
		writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		if not csv_exists:
			writer.writerow(['file name', 'attack', 'field','src', 'dst', 'p_src', 'p_dst', 'proto', 'length [packet]', 'length [bit]'])

		writer.writerow([filename, attack, field, src, dst, p_src, p_dst, proto, lengthb, lengthp])

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
attack_in_chunks, lengthp, lengthb = read_attack(settings.attack, settings.field)
flows = find_flows(settings.pcap, len(attack_in_chunks))
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
				source, destination, flow_label, src_port, dst_port, protocol = flow_selection(flows, what_flow)
				break
		elif operation == 'r':
			rnd_flow = random.choice(flows.index.tolist())
			print('Flow ' + str(rnd_flow) + ' is chosen.')
			source, destination, flow_label, src_port, dst_port, protocol = flow_selection(flows, rnd_flow)
			break
		elif operation == '':
			print('First flow is chosen.')
			first_flow = flows.index.tolist()[0]
			source, destination, flow_label, src_port, dst_port, protocol = flow_selection(flows, first_flow)
			break
		else:
			print("This operation is not supported!")
	print('-' * 25)
	print("Wireshark filter: ipv6.src == " + str(source) + " and ipv6.dst == " + str(destination) + " and ipv6.flow == " + str(flow_label) + " and tcp.srcport == " + str(src_port) + " and tcp.dstport == " + str(dst_port))
	resulting_pcap_file = inject(settings.pcap, source, destination, flow_label, src_port, dst_port, protocol, settings.field, attack_in_chunks)
	write_to_csv('injected_flows.csv', settings.pcap, settings.attack, settings.field, source, destination, src_port, dst_port, protocol, lengthp, lengthb)
	if settings.field == "TIMING":
		reorder_timing_pcap_file(resulting_pcap_file)
else:
	print("No conversations with enough packets are found in this pcap!")
























