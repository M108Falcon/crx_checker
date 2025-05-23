# crx_checker
CRX malware and risk assessment tool.

## Why another crx checker?
The old reliable [crxcavator.io](http://crxcavator.io) is still not working after going dark in Late September/Early October 2024. which leaves no place to check if the web extension you're about to donwload is safe to use or not and what risks are associated with it. Other tools usually cost money. Hence, this script. Tried my own implementation, built upon my crxcavator usage and data/results I collected over a year and half while working on web browser extension safety project for my org. This script aims to provide similar functionality that it used to provide albeit on local machine at this point. 

## What does it do?
Uploads the downloaded crx file for the browser extension to be assessed to VT via api. Retrieves assessment results to check for malicious behavior. Extracts the crx contents, performs Risk Assessment for the extension based on [Google's whitepaper](https://storage.googleapis.com/support-kms-prod/H67pelgBrKlKSgvA24ooNwVYYx6emmcuJ0LD) and finally performs SBOM scan via retire to find vulnerabilities in dependencies.

## Features
- Fully automated analysis, just provide guid for the extension.
- Support for big files (upto 650mb) altho extensions aren't that large but just in case.

## Prequisites:
- 7zip (added to PATH)
- Python 3
- Nodejs
- retire
- VirusTotal API key
- OPTIONAL: CRX Extractor/Downloader Extension for [google chrome/brave](https://chromewebstore.google.com/search/CRX%20Extractor%2FDownloader)

## Environment setup:
- Create python virtual environment.`python -m venv <name of your virtualenv>`
- Install the dependencies via give requirements file. `pip install -r requirements.txt`
- Install retire. `npm install -g retire`
- Edit code to add locations to relevant dirs in [`crx_downloader function`](crx_checker.py) and VirusTotal API key file before running the tool (use absolute paths).

## Roadmap
- [x] Full automation i.e just provide URL to extension and rest is done automatically.
- [ ] Separate download of crx samples
- [ ] Support for firefox addons.
- [ ] (OPTIONAL) Web based GUI.
