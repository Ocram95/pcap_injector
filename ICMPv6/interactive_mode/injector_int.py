import sys
import optparse
import subprocess
import pandas as pd
from scapy.utils import rdpcap
from scapy.utils import wrpcap
from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply, ICMPv6EchoRequest
import random
import base64
import csv

#Field and length of them supported
FIELD_LENGTH = {
	"TIMING": 1,
	"PAYLOAD": 8
}

ICMP_REQ_REP = {
	"REQUEST": 128,
	"REPLY": 129
}

def process_command_line(argv):
	parser = optparse.OptionParser()
	parser.add_option('-r', '--pcap', help='Specify the pcap to inject.', action='store', type='string', dest='pcap')
	parser.add_option('-f', '--field', help='Specify the field to exploit to contain the payload (i.e., PAYLOAD, TIMING).', action='store', type='string', dest='field')
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
	if field == "PAYLOAD":
		attack_in_chunks = [file_in_string[i:i+dim_field] for i in range(0, len(file_in_string), dim_field)]
	print("Number of packets needed: " + str(len(attack_in_chunks)))
	print("Number of bits needed: " + str(len(attack_in_bits)))
	return attack_in_chunks, str(len(attack_in_chunks)), str(len(attack_in_bits))

def find_flows(pcap_to_read, number_packets):
	#Creation of csv file where each line is composed of three-tuple src and dst for each packet 
	print("Creating tmp files...")
	create_tmp_csv = "tshark -r " + pcap_to_read + " -T fields -e ipv6.src -e ipv6.dst -e ipv6.nxt -Y 'icmpv6.type == " + str(ICMP_REQ_REP["REQUEST"]) + "' -E header=y -E separator=, > tmp.csv"
	process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	#Count of packets that compose each flow, grouping by src, dst and fl
	df = pd.read_csv('tmp.csv')
	df_final = df.groupby(['ipv6.src', 'ipv6.dst', 'ipv6.nxt']).size().to_frame('#pkts').reset_index()
	#Deleting of csv file
	delete_tmp_csv = "rm tmp.csv"
	process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	print("Deleting tmp files...")
	#Adding INDEX column name
	df.index.name = "INDEX"
	#Return flows which contains at leats 'number_of_packets' packets
	df_final = df_final[['ipv6.src', 'ipv6.dst', 'ipv6.nxt', '#pkts']]
	df_final = df_final.fillna('-')
	return df_final.loc[df_final['#pkts'] >= number_packets]

def inject(pcap, source, destination, protocol, targeted_field, attack_in_chunks):
	print("Reading input pcap. This might take few minutes...")
	pkts = rdpcap(pcap)
	secret_index = 0
	wire_len = []
	index = 0
	#Delay and number of delays to add for timing CC
	delta = 10
	n = 0

	resulting_pcap_file = settings.output

	print("Injecting...")
	for x in range(len(pkts)):
		wire_len.append(pkts[x].wirelen)
		# Stego content only into icmpv6 requests. Change '128' to '129' for icmpv6 replies
		if pkts[x].haslayer(ICMPv6EchoRequest):
			#Search for the correct flow
			if source == pkts[x][IPv6].src and destination == pkts[x][IPv6].dst and protocol == pkts[x][IPv6].nh:
				#If there is still something to inject
				if secret_index < len(attack_in_chunks):
					if targeted_field == "PAYLOAD":
						pkts[x][ICMPv6EchoRequest].data = attack_in_chunks[secret_index] 
					elif targeted_field == "TIMING":
						if int(attack_in_chunks[secret_index], 2) == 1:
							n += 1
					secret_index += 1
				#Modify the time of each packet. In case of non-timing CCs, n = 0 and nothing happens. Otherwise, 
				#the time change according to n and delta.
				pkts[x].time += n * delta
			#Modify the time of packets in the opposite direction. This is necessary for timing CCs to respect the order
			#of received packet.
			# if source == pkts[x][IPv6].dst and destination == pkts[x][IPv6].src and protocol == pkts[x][IPv6].nh:
			# 	pkts[x].time += n * delta
			del(pkts[x][ICMPv6EchoRequest].cksum)
		pkts[x].wirelen = wire_len[index]
		index += 1
		#WARNING: check if the linktype is what is needed
		wrpcap(resulting_pcap_file, pkts[x], append=True, linktype=0)
	print("Injection succesfully finished!")
	return resulting_pcap_file

def flow_selection(flows, number):
	source = flows.loc[number]['ipv6.src']
	destination = flows.loc[number]['ipv6.dst']
	protocol = 58
	return source, destination, protocol

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
				source, destination, protocol = flow_selection(flows, what_flow)
				break
		elif operation == 'r':
			rnd_flow = random.choice(flows.index.tolist())
			print('Flow ' + str(rnd_flow) + ' is chosen.')
			source, destination, protocol = flow_selection(flows, rnd_flow)
			break
		elif operation == '':
			print('First flow is chosen.')
			first_flow = flows.index.tolist()[0]
			source, destination, protocol = flow_selection(flows, first_flow)
			break
		else:
			print("This operation is not supported!")
	print('-' * 25)
	print("Wireshark filter: ipv6.src == " + str(source) + " and ipv6.dst == " + str(destination) + " and icmpv6")
	resulting_pcap_file = inject(settings.pcap, source, destination, protocol, settings.field, attack_in_chunks)
	#write_to_csv('injected_flows.csv', settings.pcap, settings.attack, settings.field, source, destination, protocol, lengthp, lengthb)
	if settings.field == "TIMING":
		reorder_timing_pcap_file(resulting_pcap_file)
else:
	print("No conversations with enough packets are found in this pcap!")
























