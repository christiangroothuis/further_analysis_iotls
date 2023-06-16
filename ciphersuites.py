import pyshark
import json
import os

# for each file, extract the domain name from the TLS packets
domains = {}

for filename in os.listdir('FingerprintingAnalysis/Traffic'):
    if not filename.endswith('.pcap'):
        continue

    print('processing ' + filename)
    if filename not in domains:
        domains[filename] = set()

    cap = pyshark.FileCapture('FingerprintingAnalysis/Traffic/' + filename)

    for pkt in cap:
        if 'TLS' in pkt:
            try:
                domain = pkt.tls.handshake_extensions_server_name
                domains[filename].add(domain)
            except AttributeError as e:
                pass
    cap.close()


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

data_str = json.dumps(set([1,2,3,4,5]), cls=SetEncoder)

with open('domains_accessed.json', 'w') as fp:
    json.dump(domains, fp, cls=SetEncoder)
