all:
	g++ pds-scanner.cpp -o pds-scanner -g

clean:
	rm pds-scanner


run:
	sudo ./pds-scanner -i eth1 -f out.xml