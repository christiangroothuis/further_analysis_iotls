import json

with open('accepted_ciphersuites.json') as file:
    data = json.load(file)


def get_incomplete_handshakes(data):
    root_keys = {}
    for pcap, domains in data.items():
        for domain, cipher_suites in domains.items():
            if len(cipher_suites) == 0:
                if pcap not in root_keys:
                    root_keys[pcap] = set()
                    root_keys[pcap].add(domain)
    return root_keys

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

print(json.dumps(get_incomplete_handshakes(data), indent=4, cls=SetEncoder))
