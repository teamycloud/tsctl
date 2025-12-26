
sudo tcpdump -i lo0 port 23750 -w 23750.pcap 
tcpdump -r 23750.pcap -A -vvv > 23750.txt