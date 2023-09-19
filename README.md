# NessPy

```text
 _   _               ____        
| \ | | ___  ___ ___|  _ \ _   _ 
|  \| |/ _ \/ __/ __| |_) | | | |
| |\  |  __/\__ \__ \  __/| |_| |
|_| \_|\___||___/___/_|    \__, |
                           |___/
```
NessPy is a powerful Python script designed to streamline vulnerability management and security assessments with Nessus. Leveraging the capabilities of Tenable's Nessus vulnerability scanner, this tool provides a seamless interface to interact with Nessus via its RESTful API.


## Key Features:

1. **Automated Scanning**: Easily initiate vulnerability scans across your network, servers, and applications with just a few lines of Python code. Automate the process of identifying security weaknesses in your systems.

2. **Customization**: Tailor scans to your specific needs by configuring scan policies, targets, and scan options. Flexibility is at your fingertips to adapt to your organization's unique requirements.

3. **Ease of Use**: Designed with simplicity in mind, the script offers a user-friendly interface to interact with the Nessus API. Documentation and code examples make it accessible for both beginners and experienced developers.




## Use Cases:

1. **Security Auditing**: Conduct regular security audits to identify and mitigate vulnerabilities proactively.

2. **Compliance Reporting**: Generate compliance reports (e.g., PCI DSS, CIS) to meet regulatory requirements.


Feel free to customize this tool to better suit your use cases.


## Requirements
```
1. Tested on Tenable Nessus Professional version 10.6.0 (#103) LINUX
2. Python 3
```


## Setup
```
git clone https://github.com/binderlabs/NessPy.git
cd NessPy
pip3 install progressbar requests argparse termcolor
```

Symbolic link the script to `/usr/bin` directory:
```
chmod +x /opt/NessPy/nesspy.py
sudo ln -s /opt/NessPy/nesspy.py /usr/bin/nesspy
```

Remember to change the `url`, `username`, `password` & `path` in `nesspy.py`.

## Examples

### List Policies
```
nesspy -l
```

### Scan a single target:
```
nesspy -t 127.0.0.1 -p 'my policy' -n 'My First Scan' -f 'Nessus Folder' -e 'csv,nessus,html'
```
(NOTE: Exported Report(s) will be stored on `output/` directory.)


### Scan targets in a .txt file:
```
nesspy -T list.txt -p 'my policy' -n 'My First Scan' -f 'Nessus Folder' -e 'nessus' -o 'production-list'
```
(NOTE: No need to specify file extension in output filename.)


### Scan a list of targets one by one in Nessus:
```
for i in `cat list.txt`; do nesspy -t $i -p 'compliance policy' -f 'Compliance' -e 'csv,html,nessus' -o $i;done
```
(NOTE: refer to `list.txt` attached in this repository for the format)
(NOTE: if `-n` nessus scan name is not provided, target ip address will be used.)


## Potential Future Roadmap

* Allow users to export different types of reports
* Allow users to run different types of scans instead of just policy scan.


## Feedbacks

* Email `erictee2802@gmail.com` for any recommandations, hopefully your mail is not in my junk folder. LOL.


## References

https://github.com/AdmiralGaust/python-nessus


