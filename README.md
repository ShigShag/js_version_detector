# README.md

## Python JavaScript Library Version Extractor

This Python script can **extract JavaScript library versions** from a given web page. It scans the website to identify **inline** and **externally linked** JavaScript files and attempts to extract version information from these files.

```
-----------------------------------------------------
Scanning results for https://www.example.com
-----------------------------------------------------
JavaScript files found:            5
Versions detected:                 3

File                             Version                URL
-------------------------------  ---------------------  ------------------------------
jquery.min.js                    3.6.0                  https://www.example.com/js/jquery.min.js
bootstrap.min.js                 Not found              https://www.example.com/js/bootstrap.min.js
react.min.js                     17.0.2                 https://www.example.com/js/react.min.js
vue.min.js                       3.0.11                 https://www.example.com/js/vue.min.js
Inline script at line 142        Not found - embedded   https://www.example.com
```

---

## Installation

1. Clone this repository:
```bash
git clone https://github.com/ShigShag/js_version_detector
```

1. Navigate to the directory of the cloned repository:
```bash
cd js_version_detector
```

1. Install the required Python packages:
```bash
pip install -r requirements.txt
```

1. Execute
```bash
python3 js_version_detector.py --url [URL]
```

---

## Usage

The script requires a URL to analyze and offers several additional optional arguments:

* `-u, --url`: URL of the website to analyze (required)
* `-r, --recursion`: Recursive level of links on the site (default is 0)
* `-v, --verbose`: Displays realtime data/activities
* `-p, --proxy`: Enter a proxy address (e.g. socks5h://localhost:9050 for TOR)
* `-a, --user-agent`: Custom user agent

**Help page**

```
usage: js_version_scanner.py [-h] --url URL [--recursion RECURSION] [--verbose] [--proxy PROXY] [--user-agent USER_AGENT]

options:
  -h, --help            show this help message and exit
  --url URL, -u URL     URL of the website to analyze
  --recursion RECURSION, -r RECURSION
                        Recursive level of links on the site
  --verbose, -v         Displays realtime data / activities
  --proxy PROXY, -p PROXY
                        Enter a proxy address e.g. socks5h://localhost:9050 for TOR
  --user-agent USER_AGENT, -a USER_AGENT
                        Custom user agent
```

---

### Example usages

1. Basic usage with a URL:
```bash
python main.py -u https://www.example.com
```

2. Using recursion to scan links on the site:
```bash
python main.py -u https://www.example.com -r 1
```

3. Enabling verbose mode to see realtime data:
```bash
python main.py -u https://www.example.com -v
```

4. Specifying a custom user agent:
```bash
python main.py -u https://www.example.com -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

5. Specifying a proxy (Tor in this case):
```bash
python main.py -u https://www.example.com -p socks5h://localhost:9050
```

---

## License

This project is licensed under [MIT License](LICENSE).
