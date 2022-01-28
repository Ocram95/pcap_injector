import sys
import optparse
import subprocess
import pandas as pd
from scapy.utils import rdpcap
from scapy.utils import wrpcap
from scapy.all import *
from scapy.layers.inet import IP
import random
import base64
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
			if field == 'TOS':
				dim_field = 8
			elif field == 'TTL':
				dim_field = 1
			elif field == 'ID':
				dim_field = 16
			elif field == "TIMING":
				dim_field = 1
			attack_in_chunks = [attack_in_bits[i:i+dim_field] for i in range(0, len(attack_in_bits), dim_field)]
			if field == "TIMING":
				attack_in_bits_tmp = '0' + attack_in_bits
				attack_in_bits = attack_in_bits_tmp
				attack_in_chunks.insert(0, '0')
			list_of_attacks.append((field, attack_in_chunks))
			line = fp.readline()
	return list_of_attacks

def find_flows(pcap_to_read, list_of_attacks):
	#Creation of csv file where each line is composed of three-tuple src and dst for each packet 
	print("Creating tmp files...")
	create_tmp_csv = "tshark -r " + pcap_to_read + " -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.proto -E header=y -E separator=, > tmp.csv"
	process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	#Count of packets that compose each flow, grouping by src, dst and fl
	df = pd.read_csv('tmp.csv')
	df_tcp = df.groupby(['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'ip.proto']).size().to_frame('#pkts').reset_index()
	df_udp = df.groupby(['ip.src', 'ip.dst', 'udp.srcport', 'udp.dstport', 'ip.proto']).size().to_frame('#pkts').reset_index()
	#Deleting of csv file
	delete_tmp_csv = "rm tmp.csv"
	process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	print("Deleting tmp files...")
	#Adding INDEX column name
	df.index.name = "INDEX"
	#Return flows which contains at leats 'number_of_packets' packets
	df_final = pd.concat([df_tcp, df_udp]).reset_index(drop=True)
	df_final = df_final[['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'ip.proto', '#pkts']]
	df_final = df_final.fillna('-')

	list_of_dict = []
	for x in range(len(list_of_attacks)):
		number_of_packets_needed = len(list_of_attacks[x][1])
		found_flows = False
		for y in range(len(df_final)):
			flow = df_final.iloc[y]
			if flow['#pkts'] >= number_of_packets_needed:
				if flow['tcp.srcport'] != '-':
					found_flows = True
					list_of_dict.append(create_dict_attack(flow, list_of_attacks[x], 'tcp'))
				elif flow['udp.srcport'] != '-':
					list_of_dict.append(create_dict_attack(flow, list_of_attacks[x], 'udp'))
				df_final = df_final.drop(df_final.index[y])
				break
		if not found_flows:
			print("There are no flows with enough packets to contain attack at line: " + str(x+1))
	return list_of_dict

def create_dict_attack(flow, attack, proto):
	tmp_dict = {}
	tmp_dict['src'] = str(flow['ip.src'])
	tmp_dict['dst'] = str(flow['ip.dst'])
	if proto == 'tcp':
		tmp_dict['psrc'] = int(flow['tcp.srcport'])
		tmp_dict['pdst'] = int(flow['tcp.dstport'])
	elif proto == 'udp':
		tmp_dict['psrc'] = int(flow['udp.srcport'])
		tmp_dict['pdst'] = int(flow['udp.dstport'])
	tmp_dict['proto'] = int(flow['ip.proto'])
	tmp_dict['target_field'] = attack[0]
	tmp_dict['attack'] = attack[1]
	tmp_dict['counter'] = 0
	tmp_dict['n-delay'] = 0
	#tmp_dict['injected'] = False
	return tmp_dict

def inject(pcap, attack_dict):
	print("Reading input pcap. This might take few minutes...")
	pkts = rdpcap(pcap)
	wire_len = []
	index = 0

	delta = 1

	resulting_pcap_file = settings.output

	print("Injecting...")
	for x in range(len(pkts)):
		wire_len.append(pkts[x].wirelen)
		if TCP in pkts[x] or UDP in pkts[x]:
			#Packet info
			p_source, p_destination, p_psrc, p_pdst, p_proto = pkts[x][IP].src, pkts[x][IP].dst, pkts[x].sport, pkts[x].dport, pkts[x][IP].proto
			for attack in attack_dict:
				#Attack info
				a_source, a_destination, a_psrc, a_pdst, a_proto = attack['src'], attack['dst'], attack['psrc'], attack['pdst'], attack['proto']
				#Check if the x-th packet needs to be injected
				if p_source == a_source and p_destination == a_destination and p_psrc == a_psrc and p_pdst == a_pdst and p_proto == a_proto:
					#if attack['injected'] == False:
					if attack['counter'] < len(attack['attack']):
						targeted_field = attack['target_field']
						if targeted_field == 'TOS':
							pkts[x][IP].tos = int(attack['attack'][attack['counter']],2)
						elif targeted_field == 'ID':
							pkts[x][IP].id = int(attack['attack'][attack['counter']],2)
						elif targeted_field == 'TTL':
							if attack['attack'][attack['counter']] == "0":
								pkts[x][IP].ttl = 10
							else:
								pkts[x][IP].ttl = 250
						elif targeted_field == 'TIMING':
							if attack['attack'][attack['counter']] == "1":
								attack['n-delay'] += 1
						attack['counter'] += 1
					# Modify the time of each packet. In case of non-timing CCs, n = 0 and nothing happens. Otherwise, 
					# the time change according to n and delta.
					pkts[x].time += attack['n-delay'] * delta
				# Modify the time of packets in the opposite direction. This is necessary for timing CCs to respect the order
				# of received packet.
				# if p_flow == a_flow and p_source == a_destination and p_destination == a_source and p_psrc == a_pdst and p_pdst == a_src and p_proto == a_proto:
				# 	pkts[x].time += attack['n-delay'] * delta
		pkts[x].wirelen = wire_len[index]
		index += 1
		wrpcap(resulting_pcap_file, pkts[x], append=True, linktype=1)
	print("Injection succesfully finished!")
	return resulting_pcap_file

def write_wireshark_filters(attacks_and_flows):
	print("Wireshark filters:")
	for x in attacks_and_flows:
		print('ip.src == ' + str(x['src']) + ' and ip.dst == ' + str(x['dst']) + ' and tcp.srcport == ' + str(x['psrc']) + ' and tcp.dstport == ' + str(x['pdst']) + ' and ip.proto == ' + str(x['proto']))

def write_to_csv(csv_file_name, attacks_and_flows):
	csv_exists = os.path.isfile(csv_file_name)
	with open(csv_file_name, mode='a') as file:
		writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		if not csv_exists:
			writer.writerow(['field','src', 'dst', 'p_src', 'p_dst', 'proto', 'length [packet]', 'length [bit]'])
		for x in attacks_and_flows:
			bit_lenght = 0
			for l in x['attack']:
				bit_lenght += len(l)
			writer.writerow([x['target_field'], x['src'], x['dst'], x['psrc'], x['pdst'], x['proto'], len(x['attack']), bit_lenght])

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













