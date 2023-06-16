import json
import socket
from OpenSSL import SSL

# Read the JSON file
with open('domains_accessed.json') as file:
    data = json.load(file)

# Create a new dictionary to store the updated results
updated_results = {}

for pcap, domains in data.items():

    updated_results[pcap] = {}

    for domain in domains:
        print(pcap, domain)
        try:
            ctx = SSL.Context(SSL.SSLv23_METHOD)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = SSL.Connection(ctx, s)
            ssl_sock.connect((domain, 443))
            ssl_sock.do_handshake()

            accepted_ciphers = ssl_sock.get_cipher_list()
            updated_results[pcap][domain] = accepted_ciphers
        except Exception as e:
            print(e)
            updated_results[pcap][domain] = []

with open('accepted_ciphersuites.json', 'w') as file:
    json.dump(updated_results, file, indent=4)
