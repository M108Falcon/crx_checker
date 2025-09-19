# crx_checker
CRX malware and risk assessment tool.

## Why another crx checker?
The old reliable [crxcavator.io](http://crxcavator.io) is still not working after going dark in Late September/Early October 2024. which leaves no place to check if the web extension you're about to donwload is safe to use or not and what risks are associated with it. Other tools usually cost money. Hence, this script. Tried my own implementation, built upon my crxcavator usage and data/results I collected over a year and half while working on web browser extension safety project for my org. This script aims to provide similar functionality that it used to provide albeit on local machine at this point. 

## What does it do?
Downloads the crx file on your computer. Calculates its SHA256 Hash, runs against Virustotal Database for Malware/Exploit analysis. If no results are found via Hash-based searching, then uploads the file to Virustotal for full-scan to be assessed via API. Extracts the crx contents, performs Risk Assessment for the extension based on [Google's whitepaper](https://storage.googleapis.com/support-kms-prod/H67pelgBrKlKSgvA24ooNwVYYx6emmcuJ0LD) and finally performs SBOM scan via retirejs to find vulnerabilities in dependencies.

## Features
- Support for big files (upto 650mb) altho extensions aren't that large but just in case.
- Fully automated process: Only needs extension guid, and you're good to go.
- Hash based searching.

## Prequisites:
- 7zip (added to PATH)
- VirusTotal API key
- Python (min version: 3.9 PEP 616)
- Nodejs
- retirejs
- corporate proxy root certificate (if on corporate machine)
- OPTIONAL -> CRX Extractor/Downloader Extension for [google chrome/brave](https://chromewebstore.google.com/search/CRX%20Extractor%2FDownloader)

## Environment setup:
- Create python virtual environment. `python -m venv <path+name of your virtualenv>`
- Activate your virtualenv.
```powershell
Windows:
& <path to pyenv>\Scripts\Activate.ps1
```
```shell
UNIX:
source <path to pyenv>/bin/activate
```
- Install the dependencies via give requirements file. `pip install -r <path>\requirements.txt`
- Install retire. `npm install -g retire`
- Edit code to add locations to relevant dirs <ins>(default WINDOWS paths followed)</ins> and VirusTotal API key file before running the tool. **(Use absolute paths)**
    - Line:230 VT API key file.
    - Line:41 location to downloaded crx file of extension.
    - Line: 42 location to extract the donwloaded files.

## If you're under corporate-proxy configure this otherwise ignore
- Add corporate-proxy cert to PATH/envar for nodejs
```powershell
Windows
# copy the corporate-proxy cert to AppData
cp $env:HOMEPATH\crx_checker\corporate-proxy-cert.pem $env:APPDATA
# Add to PATH permanent (recommended)
[System.Environment]::SetEnvironmentVariable("NODE_EXTRA_CA_CERTS", "C:\Users\<username>\AppData\Roaming\corporate-proxy-cert.pem", "User")
# OR Add to PATH temporary
$env:NODE_EXTRA_CA_CERTS="C:\Users\<username>\AppData\Roaming\corporate-proxy-cert.pem"
```
```bash
UNIX
# add cert to path
mkdir ~/.pki/
mv .pki/corporate-proxy-cert.pem <location>/corporate-proxy-cert.pem

# Add env to bashrc
export REQUESTS_CA_BUNDLE=$HOME/.pki/corporate-proxy-cert.pem
export SSL_CERT_FILE=$HOME/.pki/corporate-proxy-cert.pem
export NODE_EXTRA_CA_CERTS=$HOME/.pki/corporate-proxy-cert.pem
```

## Debug:
if you encounter python `ssl-certificate-invalid` error then add corporate-proxy cert explicitly to `certifi` certificate store of your virtual environemnt 
``` powershell
Windows
# ensure virtualenv is active
cp $env:APPDATA\corporate-proxy-cert.pem $(python -m certifi)
```

```bash
UNIX
# ensure virtualenv is active
cp $HOME/.pki/corporate-proxy-cert.pem $(python -m certifi)

```

## Roadmap
- [x] Full automation i.e just provide URL to extension and rest is done automatically.
- [x] Hash based searching.
- [ ] Scan history (parially complete).
- [ ] Reporting formats (partially complete).
- [ ] Bulk Scan.
- [ ] Platform Agnostic script.
- [ ] (OPTIONAL) Support for firefox addons.
- [ ] (OPTIONAL) Web based GUI.