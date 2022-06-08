# Shodan_SHIFT
Shodan SHIFT demonstrates one of many useful use cases for using Shodan to threat hunt. Specifically, SHIFT assists a user with identification of vulnerable source and destination IP addresses contained in a packet capture file.
## Installation
Python3 and tshark are required for shift to work properly. Additionaly, the provided requirements.txt file should be run to load any missing python dependencies.
## Usage
The command line below shows the basic usage for the SHIFT script.

`python3 main.py sample.pcap cves.csv <shodan API key> <output option>`

Available output options include output into a csv file, json file, or into Elasticsearch. Syntax for the JSON or CSV output are structurally identical.

CSV Output

`python3 main.py sample.pcap cves.csv <shodan API key> -csv out.csv`

JSON Output

`python3 main.py sample.pcap cves.csv <shodan API key> -json out.json`


Elasticsearch requires the ELK IP and index to write into. You can also optionally provide the username and password if authentication is configured on the ELK stack you are writing to.

`python3 main.py sample.pcap cves.csv <shodan API key> -elk -elk_index <Elasticsearch index> -elk_ip <Elasticsearch IP> -elk_un <Elasticsearch username> -elk_pw <Elasticsearch password>`


The format for the cves.csv file containing the CVEs you are interested in is a plaintext, comma seperated value file.

`CVE-2019-11510,cve-2020-5902,cve-2019-19781`


While the format for the output file will vary, the output includes the IP address and vulnerability pair discovered in the PCAP.
