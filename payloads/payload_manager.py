def load_payloads(self):
    payloads = {}
    for file in os.listdir(self.payload_dir):
        if file.endswith('.json'):
            vuln_type = file.split('.')[0]
            with open(os.path.join(self.payload_dir, file)) as f:
                payloads[vuln_type] = json.load(f)
    
    # Load subdirectories
    for subdir in ['ssrf']:
        subdir_path = os.path.join(self.payload_dir, subdir)
        for file in os.listdir(subdir_path):
            if file.endswith('.json'):
                with open(os.path.join(subdir_path, file)) as f:
                    payloads[f"{subdir}_{file.split('.')[0]}"] = json.load(f)
    return payloads
