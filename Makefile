build:
	cargo build

run: build
	sudo ./target/debug/traffic_analyzer
