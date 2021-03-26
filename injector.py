import sys
import optparse
import subprocess
import pandas as pd
from scapy.utils import rdpcap
from scapy.utils import wrpcap
from scapy.all import *
from scapy.layers.inet6 import IPv6
import random

#Field and length of them supported
FIELD_LENGTH = {
	"FL": 20,
	"TC": 8,
	"HL": 1
}

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
		'-f',
		'--field',
		help='Specify the field to exploit to contain the payload (i.e., FL, TC, HL).',
		action='store',
		type='string',
		dest='field')

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
	if not settings.field:
		raise ValueError("A field must be specified.")
	if settings.field not in FIELD_LENGTH:
		raise ValueError("The specified field is incorrect or not supported.")
	if not settings.attack:
		raise ValueError("An attack must be specified.")


	return settings, args


def read_attack(attack_to_read, dim_field):
	print("Reading the attack...")
	try:
		file = open(attack_to_read, "r")
		file_in_string = file.read()
	except IOError:
		print("This file does not exist. I will inject the string: " + str(attack_to_read))
		file_in_string = str(attack_to_read)
	#Conversion of the input in bits
	attack_in_bits = ''.join(format(ord(bit), '08b') for bit in file_in_string)
	#Division in chunks of 'dim_field' size
	attack_in_chunks = [attack_in_bits[i:i+dim_field] for i in range(0, len(attack_in_bits), dim_field)]
	print("Number of packets needed: " + str(len(attack_in_chunks)))
	return attack_in_chunks

def find_flows(pcap_to_read, number_packets):
	#Creation of csv file where each line is composed of three-tuple src and dst for each packet 
	print("Creating tmp files...")
	create_tmp_csv = "tshark -r " + pcap_to_read + " -T fields -e ipv6.flow -e ipv6.src -e ipv6.dst -E header=y -E separator=, > tmp.csv"
	process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	#Count of packets that compose each flow, grouping by src, dst and fl
	df = pd.read_csv('tmp.csv')
	df = df.groupby(['ipv6.flow', 'ipv6.src', 'ipv6.dst']).size().to_frame('#pkts').reset_index()
	#Deleting of csv file
	delete_tmp_csv = "rm tmp.csv"
	process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	print("Deleting tmp files...")
	#Adding INDEX column name
	df.index.name = "INDEX"
	#Return flows which contains at leats 'number_of_packets' packets
	return df.loc[df['#pkts'] >= number_packets]

def inject(pcap, source, destination, flow_label, targeted_field, attack_in_chunks):
	print("Reading input pcap. This might takes few minutes...")
	pkts = rdpcap(pcap)
	secret_index = 0
	wire_len = []
	index = 0
	print("Injecting...")
	for x in range(len(pkts)):
		wire_len.append(pkts[x].wirelen)
		if secret_index < len(attack_in_chunks):
			#Search for the correct flow
			if source == pkts[x][IPv6].src and destination == pkts[x][IPv6].dst and flow_label == pkts[x][IPv6].fl:
				if targeted_field == "FL":
					pkts[x][IPv6].fl = int(attack_in_chunks[secret_index],2)
				elif targeted_field == "TC":
					pkts[x][IPv6].tc = int(attack_in_chunks[secret_index],2)
				elif targeted_field == "HL":
					if int(attack_in_chunks[secret_index],2) == 0:
						pkts[x][IPv6].hlim = 10
					else:
						pkts[x][IPv6].hlim = 255
				secret_index += 1
		pkts[x].wirelen = wire_len[index]
		index += 1
		#WARNING: check if the linktype is what is needed
		wrpcap(str(targeted_field) + "_injected_" + str(pcap), pkts[x], append=True, linktype=101)
	print("Injection succesfully finished!")
	return pkts, wire_len

def flow_selection(flows, number):
	source = flows.loc[number]['ipv6.src']
	destination = flows.loc[number]['ipv6.dst']
	flow_label_extended = flows.loc[number]['ipv6.flow']					#0x000f92c1
	flow_label = int(flow_label_extended[:2] + flow_label_extended[5:], 16)	#0xf92c1 -> 1020609
	return source, destination, flow_label




settings, args = process_command_line(sys.argv)
attack_in_chunks = read_attack(settings.attack, FIELD_LENGTH[settings.field])
flows = find_flows(settings.pcap, len(attack_in_chunks))
if len(flows) > 0:
	print('-' * 25)
	print("CONVERSATIONS FOUND")
	print(flows)
	print('-' * 25)
	while True:
		operation = input("Choose the flow by its index (leave it blank for the first flow or 'r' for a random choice): ")
		if operation.strip().isdigit():
			what_flow = int(operation)
			if not what_flow in flows.index:
				print("Invalid flow index")
				continue
			else:
				source, destination, flow_label = flow_selection(flows, what_flow)
				break
		elif operation == 'r':
			rnd_flow = random.choice(flows.index.tolist())
			print('Flow ' + str(rnd_flow) + ' is choosen.')
			source, destination, flow_label = flow_selection(flows, rnd_flow)
			break
		elif operation == '':
			print('First flow is chosen.')
			first_flow = flows.index.tolist()[0]
			source, destination, flow_label = flow_selection(flows, first_flow)
			break
		else:
			print("This operation is not supported!")
	print('-' * 25)
	print("Conversation: src = " + str(source) + " dst = " + str(destination) + " flow label = " + str(flow_label))
	injected_pcap, wire_len = inject(settings.pcap, source, destination, flow_label, settings.field, attack_in_chunks)
else:
	print("No conversations with enough packets are found in this pcap!")

























