# vt-ip-rep

This Python script takes a list of IP addresses and queries the VirusTotal API for their reputation. 

## Requirements

- Python 3.X
- For dependencies see `requirements.txt`

## Installation

### Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip3 install -r requirements.txt
```

## Usage

You have to provide a plain text file containing one IP address (IoC) per line.

Use -f <path> to specify the path of your IoC file

```bash
python3 vt.py -f example.txt
```

## License

MIT
