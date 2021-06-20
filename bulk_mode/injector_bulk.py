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

def process_command_line(argv):
	parser = optparse.OptionParser()
	parser.add_option(
		'-r',
		'--pcap',
		help='Specify the pcap to inject.',
		action='store',
		type='string',
		dest='pcap')

	parser.add_option(
		'-a',
		'--attack',
		help='Specify the attack (i.e., text file, string).',
		action='store',
		type='string',
		dest='attack')

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
			if field == 'FL':
				dim_field = 20
			elif field == 'TC':
				dim_field = 8
			elif field == 'HL':
				dim_field = 1
			attack_in_chunks = [attack_in_bits[i:i+dim_field] for i in range(0, len(attack_in_bits), dim_field)]
			list_of_attacks.append((field, attack_in_chunks))
			line = fp.readline()
	return list_of_attacks

def find_flows(pcap_to_read, list_of_attacks):
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
	df_final = pd.concat([df_tcp, df_udp]).reset_index(drop=True)
	df_final = df_final[['ipv6.flow', 'ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'ipv6.nxt', '#pkts']]
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
	tmp_dict['flow'] = int(flow['ipv6.flow'], 0)
	tmp_dict['src'] = str(flow['ipv6.src'])
	tmp_dict['dst'] = str(flow['ipv6.dst'])
	if proto == 'tcp':
		tmp_dict['psrc'] = int(flow['tcp.srcport'])
		tmp_dict['pdst'] = int(flow['tcp.dstport'])
	elif proto == 'udp':
		tmp_dict['psrc'] = int(flow['udp.srcport'])
		tmp_dict['pdst'] = int(flow['udp.dstport'])
	tmp_dict['nxt'] = int(flow['ipv6.nxt'])
	tmp_dict['target_field'] = attack[0]
	tmp_dict['attack'] = attack[1]
	tmp_dict['counter'] = 0
	#tmp_dict['injected'] = False
	return tmp_dict

def inject(pcap, output, attack_dict):
	print("Reading input pcap. This might take few minutes...")
	pkts = rdpcap(pcap)
	wire_len = []
	index = 0
	print("Injecting...")
	for x in range(len(pkts)):
		wire_len.append(pkts[x].wirelen)
		#Packet info
		#Excluding ICMPv6 (58), fragmented packets (44) and no next header (59) for src/dst problems
		if pkts[x][IPv6].nh != 58 and pkts[x][IPv6].nh != 44 and pkts[x][IPv6].nh != 59:
			p_flow, p_source, p_destination, p_psrc, p_pdst, p_nxt = pkts[x][IPv6].fl,  pkts[x][IPv6].src, pkts[x][IPv6].dst, pkts[x].sport, pkts[x].dport, pkts[x][IPv6].nh
			for attack in attack_dict:
				#Attack info
				a_flow, a_source, a_destination, a_psrc, a_pdst, a_nxt = attack['flow'], attack['src'], attack['dst'], attack['psrc'], attack['pdst'], attack['nxt']
				#Check if the x-th packet needs to be injected
				if p_flow == a_flow and p_source == a_source and p_destination == a_destination and p_psrc == a_psrc and p_pdst == a_pdst and p_nxt == a_nxt:
					#if attack['injected'] == False:
					if attack['counter'] < len(attack['attack']):
						targeted_field = attack['target_field']
						if targeted_field == 'FL':
							pkts[x][IPv6].fl = int(attack['attack'][attack['counter']],2)
						elif targeted_field == 'TC':
							pkts[x][IPv6].tc = int(attack['attack'][attack['counter']],2)
						elif targeted_field == 'HL':
							if attack['attack'][attack['counter']] == "0":
								#print(0)
								pkts[x][IPv6].hlim = 10
							else:
								#print(1)
								pkts[x][IPv6].hlim = 250
						attack['counter'] += 1

		pkts[x].wirelen = wire_len[index]
		index += 1
		wrpcap(output + '_' + str(pcap), pkts[x], append=True, linktype=101)
	print("Injection succesfully finished!")

def write_wireshark_filters(attacks_and_flows):
	print("Wireshark filters:")
	for x in attacks_and_flows:
		print('ipv6.src == ' + str(x['src']) + ' and ipv6.dst == ' + str(x['dst']) + ' and tcp.srcport == ' + str(x['psrc']) + ' and tcp.dstport == ' + str(x['pdst']) + ' and ipv6.nxt == ' + str(x['nxt']))

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
			writer.writerow([x['target_field'], x['src'], x['dst'], x['psrc'], x['pdst'], x['nxt'], len(x['attack']), bit_lenght])


settings, args = process_command_line(sys.argv)
list_of_attacks = read_attack(settings.attack)
attacks_and_flows = find_flows(settings.pcap, list_of_attacks)
inject(settings.pcap, settings.attack, attacks_and_flows)
write_to_csv('injected_flows.csv', attacks_and_flows)
write_wireshark_filters(attacks_and_flows)













