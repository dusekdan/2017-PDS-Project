all:
	g++ pds-scanner.cpp -o pds-scanner -g
	g++ pds-spoof.cpp -o pds-spoof -g

clean:
	rm pds-scanner
	rm pds-spoof


run-scanner:
	sudo ./pds-scanner -i eth1 -f out.xml

run-spoof:
	sudo ./pds-spoof -i eth1 -t 1000 -p ndp -victim1ip fe80::c628:cac5:2523:265a -victim1mac 0800.27a9.1bdb -victim2ip fe80::f1a3:9e59:5f7:474d -victim2mac 0800.271d.d984

run-spoof-v4:
	sudo ./pds-spoof -i eth1 -t 1000 -p arp -victim1ip 169.254.179.143 -victim1mac 0800.27a9.1bdb -victim2ip 169.254.145.246  -victim2mac 0800.271d.d984