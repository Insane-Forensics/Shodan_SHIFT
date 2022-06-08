'''
Copyright © 2022 Insane Forensics, LLC

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the “Software”), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

from argparse import ArgumentParser
from pyshark import FileCapture
from ipaddress import ip_network, ip_address
from shodan import Shodan
from json import dumps
from elasticsearch import Elasticsearch, helpers

if __name__ == "__main__":
    argparser = ArgumentParser()
    argparser.add_argument("pcap", help="Pcap file to parse")
    argparser.add_argument("cvefile", help="File with csv seperated CVEs")
    argparser.add_argument("shodanapikey", help="Shodan API key")
    operation = argparser.add_mutually_exclusive_group(required=True)
    operation.add_argument("-csv", help="Output results to csv file")
    operation.add_argument("-json", help="Output results to json file")
    operation.add_argument("-elk", help="Output results to ELK", action="store_true")
    argparser.add_argument("-elk_ip", help="Elasticsearch host to connect to")
    argparser.add_argument("-elk_index", help="ELK index to load data into")
    argparser.add_argument("-elk_un", help="ELK username", default=None)
    argparser.add_argument("-elk_pw", help="ELK username", default=None)
    argparser.add_argument("-elk_bufferlen", help="ELK buffer length", default="5000")

    args = argparser.parse_args()

    # First collect all non-RFC1918 IP addresses
    ips = []
    print("Extracting IPs from PCAP")
    for packet in FileCapture(args.pcap):
        try:
            if "IP" in str(packet.layers):
                srcip = str(packet.ip.src)
                # Filter out RFC1918 source and destination IPs
                if srcip and ip_address(srcip) not in ip_network("10.0.0.0/8") \
                        and ip_address(srcip) not in ip_network("172.16.0.0/12") \
                        and ip_address(srcip) not in ip_network("192.168.0.0/16") \
                        and ip_address(srcip) not in ip_network("224.0.0.0/24") \
                        and ip_address(srcip) not in ip_network("127.0.0.1/32") \
                        and ip_address(srcip) != ip_address("255.255.255.255") \
                        and srcip not in ips:
                    ips.append(srcip)
                dstip = str(packet.ip.dst)
                if packet.ip.dst and ip_address(dstip) not in ip_network("10.0.0.0/8") \
                        and ip_address(dstip) not in ip_network("172.16.0.0/12") \
                        and ip_address(dstip) not in ip_network("192.168.0.0/16") \
                        and ip_address(dstip) not in ip_network("224.0.0.0/24") \
                        and ip_address(dstip) not in ip_network("127.0.0.1/32") \
                        and ip_address(dstip) != ip_address("255.255.255.255") \
                        and dstip not in ips:
                    ips.append(dstip)
        except:
            pass

    # Now load the CVEs we are interested in
    print("Loading CVEs Of Interest From CVE File")
    cves = ""
    with open(args.cvefile, "r") as infile:
        cves = infile.read()
    # Convert the CVEs to upper case and split on the comma
    cves = cves.upper()
    if "," in cves:
        cves = cves.split(",")

    # Now check the IPs from earlier against the CVEs of interest
    shodan = Shodan(args.shodanapikey)
    results = {}
    print("Checking IPs In Shodan")
    for ip in ips:
        h = shodan.host(ip)
        if "vulns" in h.keys():
            for v in h.get("vulns"):
                if v in cves:
                    if ip not in results.keys():
                        results[ip] = [v]
                    else:
                        results[ip].append(v)

    # Process the results
    if args.csv is not None:
        print("Loading Results Into CSV File")
        with open(args.csv, "w") as outfile:
            for ip in results.keys():
                for v in results.get(ip):
                    outfile.write(ip + "," + v + "\n")
    elif args.json is not None:
        print("Loading Results Into JSON File")
        with open(args.json, "w") as outfile:
            for ip in results.keys():
                for v in results.get(ip):
                    outfile.write(dumps({ip: results[ip]}) + "\n")
    elif args.elk is not None:
        print("Loading Results Into ELK")
        # Setup the ELK Connection
        if args.elk_un is not None and args.elk_pw is not None:
            es = Elasticsearch(
                [args.elk_ip],
                basic_auth=(args.elk_un, args.elk_pw),
                verify_certs=False
            )
        else:
            es = Elasticsearch([args.elk_ip])
        # Format the data
        buffer = []
        for ip in results.keys():
            for v in results.get(ip):
                buffer.append({"server.ip": ip, "vulnerability.id": results[ip], "_index": args.elk_index})
        for v in buffer:
            print(str(v))
        # Write the buffer to ELK
        helpers.bulk(es, buffer)
