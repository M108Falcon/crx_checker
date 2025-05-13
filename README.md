# crx_checker
CRX malware and risk assessment tool.

## Why another crx checker?
The old reliable [crxcavator.io](http://crxcavator.io) is still not working after going dark in Late September/Early October 2024. which leaves no place to check if the web extension you're about to donwload is safe to use or not and what risks are associated with it. Other tools usually cost money. Hence, this script. Tried my own implementation, built upon my crxcavator usage and data/results I collected over a year and half while working on web browser extension safety project for my org. This script aims to provide similar functionality that it used to provide albeit on local machine at this point. 

## What does it do?
Uploads the downloaded zip file for the browser extension to be assessed to VT via api. retrieves assessment results to check for malicious behavior. Extracts the crx contents, performs Risk Assessment for the extension based on [Google's whitepaper](https://storage.googleapis.com/support-kms-prod/H67pelgBrKlKSgvA24ooNwVYYx6emmcuJ0LD) and finally performs SBOM scan via retire to find vulnerabilities in dependencies.

## Features
- Support for big files (upto 650mb) altho extensions aren't that large but just in case.
- Fully automated analysis, just provide guid for the extension.

## Prequisites:
- 7zip (added to PATH)
- VirusTotal API key
- Python 3
- Nodejs
- retire
- OPTIONAL: CRX Extractor/Downloader Extension for [google chrome/brave](https://chromewebstore.google.com/search/CRX%20Extractor%2FDownloader)

## Environment setup:
- Create python virtual environment.`python -m venv <name of your virtualenv>`
- Install the dependencies via give requirements file. `pip install -r <paths to requirements txt>`
- Install retire. `npm install -g retire`
- Edit code to add locations to relevant dirs and VirusTotal API key file before running the tool (use absolute paths).
    - Line:115 VT API key file.
    - Line:127 location to downloaded crx/zip file of extension.
    - Line: 128 location to unzip the donwloaded files.

## Roadmap
- [x] Full automation i.e just provide URL to extension and rest is done automatically.
- [ ] Support for firefox addons.
- [ ] (OPTIONAL) Web based GUI.
