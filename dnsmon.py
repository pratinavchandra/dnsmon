from scapy.all import *
uniq_domains =[]
def dns_monitor(packet):
    if packet.haslayer(DNS):
        domain = packet[DNS].qd.qname.decode()
        if domain not in uniq_domains:
            uniq_domains.append(domain)
            with open('dns.log', 'w') as f:
                for domain in uniq_domains:
                    f.write("%s\n" % domain[0:len(domain)-1])
sniff(filter="udp port 53", prn=dns_monitor)
