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
	"FL": 20,
	"TC": 8,
	"HL": 1,
	"TIMING": 1
}

def process_command_line(argv):
	parser = optparse.OptionParser()
	parser.add_option(
		'-r',
		'--pcap',
		help='Specify the pcap to parse.',
		action='store',
		type='string',
		dest='pcap')

	parser.add_option(
		'-f',
		'--field',
		help='Specify the field to inspect (i.e., FL, TC, HL, TIMING).',
		action='store',
		type='string',
		dest='field')

	parser.add_option(
		'-p',
		'--packets',
		help='Specify the number of packets to extract.',
		action='store',
		default = 0,
		type='int',
		dest='packets')

	parser.add_option(
		'-b',
		'--bits',
		help='Specify the number of bits to extract.',
		action='store',
		default = 0,
		type='int',
		dest='bits')

	parser.add_option(
		'-i',
		'--image',
		help='Specify to extract an image.',
		action='store',
		default = 'n',
		type='string',
		dest='image')

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


	return settings, args


def find_flows(pcap_to_read, number_of_packets):
	#Creation of csv file where each line is composed of three-tuple src and dst for each packet 
	print("Creating tmp files...")
	create_tmp_csv = "tshark -r " + pcap_to_read + " -T fields -e ipv6.src -e ipv6.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ipv6.nxt -E header=y -E separator=, > tmp.csv"
	process = subprocess.Popen(create_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	#Count of packets that compose each flow (fl should not be considered: consider the case 
	#where fl is injected!)
	df = pd.read_csv('tmp.csv')
	df_tcp = df.groupby(['ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'ipv6.nxt']).size().to_frame('#pkts').reset_index()
	df_udp = df.groupby(['ipv6.src', 'ipv6.dst', 'udp.srcport', 'udp.dstport', 'ipv6.nxt']).size().to_frame('#pkts').reset_index()
	#Deleting of csv file
	delete_tmp_csv = "rm tmp.csv"
	process = subprocess.Popen(delete_tmp_csv, shell=True, stdout=subprocess.PIPE)
	process.wait()
	print("Deleting tmp files...")
	#Adding INDEX column name
	df.index.name = "INDEX"
	#Return flows which contains at leats 'number_of_packets' packets
	df_final = df_tcp.append(df_udp, ignore_index=True)
	df_final = df_final[['ipv6.src', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'ipv6.nxt', '#pkts']]
	df_final = df_final.fillna('-')
	return df_final.loc[df_final['#pkts'] >= number_of_packets]

def extract_packets(pcap, source, destination, src_port, dst_port, protocol, targeted_field, number_of_packets):
	print("Reading input pcap. This might takes few minutes...")
	pkts = rdpcap(pcap)
	secret_index = 0
	secret_extracted = ''
	delta = 1
	prev_time_packet = 0
	print("Extracting...")
	for x in range(len(pkts)):
		if secret_index < number_of_packets:
			if source == pkts[x][IPv6].src and destination == pkts[x][IPv6].dst and src_port == pkts[x].sport and dst_port == pkts[x].dport and protocol == pkts[x].nh:
				if targeted_field == "FL":
					#Conversion of the fl value into 20 bit value
					secret_extracted += '{0:020b}'.format(pkts[x][IPv6].fl)
				elif targeted_field == "TC":
					secret_extracted += '{0:08b}'.format(pkts[x][IPv6].tc)
				elif targeted_field == "HL":
					if pkts[x][IPv6].hlim == 250:
						secret_extracted += '1'
					elif pkts[x][IPv6].hlim == 10:
						secret_extracted += '0'
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
	print('-' * 25)
	print("PAYLOAD EXTRACTED")
	return secret_string

def extract_bits(pcap, source, destination, src_port, dst_port, protocol, targeted_field, number_of_bits):
	print("Reading input pcap. This might takes few minutes...")
	pkts = rdpcap(pcap)
	secret_index = 0
	secret_extracted = ''
	delta = 1
	prev_time_packet = 0
	print("Extracting...")
	for x in range(len(pkts)):
		if secret_index < number_of_bits:
			if source == pkts[x][IPv6].src and destination == pkts[x][IPv6].dst and src_port == pkts[x].sport and dst_port == pkts[x].dport and protocol == pkts[x].nh:
				if targeted_field == "FL":
					#The number of bits of the last packet
					rest = number_of_bits % 20
					if number_of_bits - len(secret_extracted) == rest:	#if it is the last packet
						tmp = '{0:020b}'.format(pkts[x][IPv6].fl)[20 - rest:] #take the last 'rest' bit and don't consider the first bits
						secret_extracted += tmp
						secret_index += rest
					else:
						secret_extracted += '{0:020b}'.format(pkts[x][IPv6].fl)
						secret_index += 20
				elif targeted_field == "TC":
					secret_extracted += '{0:08b}'.format(pkts[x][IPv6].tc)
					secret_index += 8
				elif targeted_field == "HL":
					if pkts[x][IPv6].hlim == 250:
						secret_extracted += '1'
					elif pkts[x][IPv6].hlim == 10:
						secret_extracted += '0'
					secret_index += 1
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
	print('-' * 25)
	print("PAYLOAD EXTRACTED")
	return secret_string


def flow_selection(flows, number):
	#TODO: extend to more protocols?
	source = flows.loc[number]['ipv6.src']
	destination = flows.loc[number]['ipv6.dst']
	if not flows.loc[number]['tcp.srcport'] == '-':
		protocol = 6
		src_port = flows.loc[number]['tcp.srcport']
		dst_port = flows.loc[number]['tcp.dstport']
	elif not flows.loc[number]['udp.srcport'] == '-':
		protocol = 17
		src_port = flows.loc[number]['udp.srcport']
		dst_port = flows.loc[number]['udp.dstport']
	return source, destination, int(src_port), int(dst_port), protocol



settings, args = process_command_line(sys.argv)
flows = find_flows(settings.pcap, settings.packets)
if len(flows) > 0:
	print('-' * 25)
	print("CONVERSATIONS FOUND")
	print(flows.head(50))
	print("Only the first 50 conversations are shown.")
	print('-' * 25)
	while True:
		operation = input("Choose the flow to inspect: ")
		if operation.strip().isdigit():
			what_flow = int(operation)
			if not what_flow in flows.index:
				print("Invalid flow index")
				continue
			else:
				source, destination, src_port, dst_port, protocol = flow_selection(flows, what_flow)
				break
		else:
			print("This operation is not supported!")
	print('-' * 25)
	print("Wireshark filter: ipv6.src == " + str(source) + " and ipv6.dst == " + str(destination) + " and tcp.srcport == " + str(src_port) + " and tcp.dstport == " + str(dst_port))
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

























