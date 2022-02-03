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

#Field and length of them supported
FIELD_LENGTH = {
	"TIMING": 1,
	"PAYLOAD": 48
}

ICMP_REQ_REP = {
	"REQUEST": 128,
	"REPLY": 129
}

def process_command_line(argv):
	parser = optparse.OptionParser()
	parser.add_option('-r', '--pcap', help='Specify the pcap to parse.', action='store', type='string', dest='pcap')
	parser.add_option('-f', '--field', help='Specify the field to inspect (i.e., PAYLOAD, TIMING).', action='store', type='string', dest='field')
	parser.add_option('-p', '--packets', help='Specify the number of packets to extract.', action='store', default = 0, type='int', dest='packets')

	settings, args = parser.parse_args(argv)
		
	if not settings.pcap:
		raise ValueError("A pcap file must be specified.")
	if not settings.field:
		raise ValueError("A field must be specified.")
	if settings.field not in FIELD_LENGTH:
		raise ValueError("The specified field is incorrect or not supported.")
	if not settings.packets:
		raise ValueError("The number of packets to extract must be specified.")


	return settings, args


def find_flows(pcap_to_read, number_of_packets):
	#Creation of csv file where each line is composed of three-tuple src and dst for each packet 
	print("Creating tmp files...")
	create_tmp_csv = "tshark -r " + pcap_to_read + " -T fields -e ipv6.src -e ipv6.dst -e ipv6.nxt -Y 'icmpv6.type == " + str(ICMP_REQ_REP["REQUEST"]) + "' -E header=y -E separator=, > tmp.csv"
	process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	df = pd.read_csv('tmp.csv')
	df_final = df.groupby(['ipv6.src', 'ipv6.dst', 'ipv6.nxt']).size().to_frame('#pkts').reset_index()
	#Deleting of csv file
	delete_tmp_csv = "rm tmp.csv"
	process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	print("Deleting tmp files...")
	#Return flows which contains at leats 'number_of_packets' packets
	df_final = df_final[['ipv6.src', 'ipv6.dst', 'ipv6.nxt', '#pkts']]
	df_final = df_final.fillna('-')
	return df_final.loc[df_final['#pkts'] >= number_of_packets]

def extract_packets(pcap, source, destination, protocol, targeted_field, number_of_packets):
	print("Reading input pcap. This might takes few minutes...")
	pkts = rdpcap(pcap)
	secret_index = 0
	secret_extracted = ''
	delta = 10
	prev_time_packet = 0
	print("Extracting...")
	for x in range(len(pkts)):
		# Stego content only into icmp requests. Change '8' to '0' for icmp replies
		if pkts[x].haslayer(ICMPv6EchoRequest):
			if secret_index < number_of_packets:
				if source == pkts[x][IPv6].src and destination == pkts[x][IPv6].dst and protocol == pkts[x][IPv6].nh:
					if targeted_field == "PAYLOAD":
						secret_extracted += pkts[x][ICMPv6EchoRequest].data.decode("utf-8")
					elif targeted_field == "TIMING":
						if pkts[x].time - prev_time_packet >= delta:
							secret_extracted += '1'
						else:
							secret_extracted += '0'
						prev_time_packet = pkts[x].time
					secret_index += 1
	#If TIMING CC, the first bit is reserved as a signature, skip it 
	if targeted_field == "TIMING":
		secret_extracted = secret_extracted[1:]
		#Creation of 8 bit chunks to correctly interpret characters
		secret_in_chunks = list((secret_extracted[0+i:8+i] for i in range(0, len(secret_extracted), 8)))
		secret_string = ''
		for i in range(len(secret_in_chunks)):
			secret_string += chr(int(secret_in_chunks[i],2))
	#If it is payload, then there is no need to convert bits to string, it is already a string
	elif targeted_field == "PAYLOAD":
		secret_string = list((secret_extracted[0+i:48+i] for i in range(0, len(secret_extracted), 48)))
	print('-' * 25)
	print("PAYLOAD EXTRACTED")
	return secret_string

def flow_selection(flows, number):
	source = flows.loc[number]['ipv6.src']
	destination = flows.loc[number]['ipv6.dst']
	protocol = 58
	return source, destination, protocol

settings, args = process_command_line(sys.argv)
flows = find_flows(settings.pcap, settings.packets)
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
				source, destination, protocol = flow_selection(flows, what_flow)
				break
		else:
			print("This operation is not supported!")
	print('-' * 25)
	print("Wireshark filter: ipv6.src == " + str(source) + " and ipv6.dst == " + str(destination))
	payload = extract_packets(settings.pcap, source, destination, protocol, settings.field, settings.packets)
	print(payload)
else:
	print("No conversations are found within this pcap!")

























