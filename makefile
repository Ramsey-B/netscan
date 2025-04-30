# Define variables
DOCKER_IMAGE_NAME = network-scanner
OUTPUT_FILE = network_data.json
CONTAINER_NAME = network_scanner_container

# Default target
.PHONY: all
all: build run_and_copy

# Build the Docker image
.PHONY: build
build:
	docker build -t $(DOCKER_IMAGE_NAME) .

# Run the Docker container, copy the output file, and remove the container
.PHONY: run
run:
	docker run --name $(CONTAINER_NAME) --network bridge $(DOCKER_IMAGE_NAME)
	@echo "Copying file..."
	docker cp $(CONTAINER_NAME):/usr/src/app/$(OUTPUT_FILE) .
	@echo "Removing container..."
	docker rm -f $(CONTAINER_NAME)

# Clean up generated files
.PHONY: clean
clean:
	rm -f $(OUTPUT_FILE)

.PHONY: activate
activate:
	source venv/bin/activate
