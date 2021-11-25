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
		#Skip header
		next(csv_reader, None)
		for row in csv_reader:
			tmp_dict = {}
			tmp_dict['target_field'] = row[0]
			tmp_dict['src'] = row[1]
			tmp_dict['dst'] = row[2]
			tmp_dict['psrc'] = int(row[3])
			tmp_dict['pdst'] = int(row[4])
			tmp_dict['nxt'] = int(row[5])
			tmp_dict['plenght'] = int(row[6])
			tmp_dict['blength'] = int(row[7])
			tmp_dict['counter'] = 0
			tmp_dict['extracted'] = ''
			tmp_dict['prev_time_packet'] = 0
			list_of_dict.append(tmp_dict)
	
	return list_of_dict

def extract(pcap, attack_dict):
	pkts = rdpcap(pcap)
	delta = 1
	for x in range(len(pkts)):
		#if pkts[x][IPv6].nh != 58 and pkts[x][IPv6].nh != 44 and pkts[x][IPv6].nh != 59 and pkts[x][IPv6].nh != 50:
		if TCP in pkts[x] or UDP in pkts[x]:	
			p_source, p_destination, p_psrc, p_pdst, p_nxt = pkts[x][IPv6].src, pkts[x][IPv6].dst, pkts[x].sport, pkts[x].dport, pkts[x][IPv6].nh
			for attack in attack_dict:
				a_source, a_destination, a_psrc, a_pdst, a_nxt = attack['src'], attack['dst'], attack['psrc'], attack['pdst'], attack['nxt']
				if p_source == a_source and p_destination == a_destination and p_psrc == a_psrc and p_pdst == a_pdst and p_nxt == a_nxt:
					if attack['counter'] < attack['blength']:
						targeted_field = attack['target_field']
						if targeted_field == "FL":
							rest = attack['blength'] % 20
							if attack['blength'] - len(attack['extracted']) == rest:	#if it is the last packet
								tmp = '{0:020b}'.format(pkts[x][IPv6].fl)[20 - rest:] #take the last 'rest' bit and don't consider the first bits
								attack['extracted'] += tmp
								attack['counter'] += rest
							else:
								attack['extracted'] += '{0:020b}'.format(pkts[x][IPv6].fl)
								attack['counter'] += 20
						elif targeted_field == "TC":
							attack['extracted'] += '{0:08b}'.format(pkts[x][IPv6].tc)
							attack['counter'] += 8
						elif targeted_field == "HL":
							if pkts[x][IPv6].hlim == 250:
								attack['extracted'] += '1'
							elif pkts[x][IPv6].hlim == 10:
								attack['extracted'] += '0'
							attack['counter'] += 1
						elif targeted_field == "TIMING":
							if pkts[x].time - attack['prev_time_packet'] >= delta:
								attack['extracted'] += '1'
							else:
								attack['extracted'] += '0'
							attack['prev_time_packet'] = pkts[x].time
							attack['counter'] += 1

	extracted_attacks_in_chunks = []
	for attack in attack_dict:
		#IF TIMING CC, exclude the first bit, used as a signature
		if attack['target_field'] == "TIMING":
			extracted_attacks_in_chunks.append((attack['target_field'],list((attack['extracted'][1:][0+i:8+i] for i in range(0, len(attack['extracted']) - 1, 8)))))
		else:
			extracted_attacks_in_chunks.append((attack['target_field'],list((attack['extracted'][0+i:8+i] for i in range(0, len(attack['extracted']), 8)))))
	extracted_attacks = []
	for attack in extracted_attacks_in_chunks:
		secret_string = ''
		for chunk in attack[1]:
			secret_string += chr(int(chunk, 2))
		extracted_attacks.append((attack[0], secret_string))
	return extracted_attacks

def write_extracted(attacks):
	file = open("extracted_attacks.txt", "w")
	for x in attacks:
		file.write(x[0] + ', ' + x[1] + '\n')

settings, args = process_command_line(sys.argv)
attack_dict = create_dict_attack(settings.injected_flows)
attacks = extract(settings.pcap, attack_dict)
write_extracted(attacks)






















