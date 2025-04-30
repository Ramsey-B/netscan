setup:
	chmod +x setup.sh
	./setup.sh

run:
	sudo python3.9 network_scan.py

clean:
	deactivate
	rm -rf venv
	rm -rf network_hosts.json
	rm -rf network_connections.json
	rm -rf network_data.json
