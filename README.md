# scope_mapper
A passive recon tool that resolves hostnames or IPs, queries RDAP/ARIN to map them to CIDR blocks and owning organizations, and exports the results to CSV for scoping, OSINT, and network intelligence.

---

## Features

- Resolve hostnames and subdomains to IPs  
- Query RDAP (via ARIN) for ownership and netblock info  
- Extract CIDR ranges, org names, and ARIN handles  
- Output clean CSVs for easy analysis  
- Gracefully handles errors and missing data with `N/A`  
- Supports one-to-one mappings: each input always produces an output row  

---

## Usage

```bash
python scope_mapper.py input.txt arin_results.csv network_results.csv
```

- `input.txt`: A list of IPs or hostnames (one per line)
- `output.csv`: CSV file containing results
- `network.csv`: CSV file containing network results

---

## Example

 **Input (ips.txt):**
 ```bash
google.com
idontexist.invalid
142.250.191.174
```

**Command:**
```bash
python scope_mapper.py ips.txt arin_results.csv network_results.csv
```

**Output:**
```bash
#arin_results.csv
Input,ResolvedIP,CIDR,Handle,Organization,OrgRef
google.com,142.250.190.78,142.250.0.0/15,GOOGLE,Google LLC,Google LLC (GOGL)
idontexist.invalid,N/A,N/A,N/A,N/A,N/A
142.250.191.174,142.250.191.174,142.250.0.0/15,GOOGLE,Google LLC,Google LLC (GOGL)
```

```bash
#network_results.csv
Input,ResolvedIP,Handle,CIDR,OrgRef
google.com,142.250.190.78,GOOGLE,142.250.0.0/15,Google LLC (GOGL)
idontexist.invalid,N/A,N/A,N/A,N/A
142.250.191.174,142.250.191.174,GOOGLE,142.250.0.0/15,Google LLC (GOGL)
```

---

# Requirements

- Python 3.7+
- requests library

---

# Disclaimer

This tool performs only passive lookups using public RDAP endpoints.
Use responsibly and within the bounds of your organization’s scope of engagement.
