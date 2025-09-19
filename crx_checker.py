# -------------------------------------
# Interpreter: Python
# Version: 202509.1
# Function: Assess browser extensions for malware, risks and sbom vulnerabilities
# Output: stdout
# Created by M108Falcon
# -------------------------------------

import os
from urllib.parse import quote # url encode
import subprocess
import json
import re
import time
import requests
from hashlib import sha256

# regex pattern(s)
# match title tag
PATTERN_TAG = re.compile(r"<title>(.*?)</title>")
# match dangerous chars (\xa0 -> nbsp \x200B -> zwsp)
PATTERN_DANGER_CHAR = re.compile(r"[\|\/\s\.\*\?\\[\]\{\}\(\)\&\!,;:\xa0(\xe2\x80\x8b)]")

# calculate_hash
def crx_hash (upload_file=None):
   # initialize hash library
   crx_sha256_hash = sha256()
   
   # calculate hash as binary file for given crx by reading it in 4096byte blocks
   with open(upload_file, "rb") as f:
      for byte_block in iter(lambda: f.read(4096), b""):
         crx_sha256_hash.update(byte_block)
   
   return crx_sha256_hash.hexdigest() 

# automated process via guids
def crx_downloader(browser_choice=2, crx_guid=None, title_pattern=PATTERN_TAG, sanitizer_pattern=PATTERN_DANGER_CHAR):
    # working vars
    crx_url = None
    crx_page_url = None
    crx_dir = "C:\\Users\\A0831400\\Downloads\\crx-scanner-work\\zips"
    unzip_crx_dir = "C:\\Users\\A0831400\\Downloads\\crx-scanner-work\\unzipped_crxs"
    chrome_crx_url = "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=136.0.7103.49&acceptformat=crx2,crx3&x=id%3D{extensionid}%26uc"
    chrome_crx_page_url = "https://chromewebstore.google.com/detail/{extensionid}"
    edge_crx_url = "https://edge.microsoft.com/extensionwebstorebase/v1/crx?response=redirect&x=id%3D{extensionid}%26installsource%3Dondemand%26uc"
    edge_crx_page_url = "https://microsoftedge.microsoft.com/addons/detail/{extensionid}"

    # guid format checks
    if len(crx_guid)!=32 or str.isalpha(crx_guid) == False:
        print("please check your guid - ERR: invalid length/digits found")
        exit()
    
    # choose browser to download crx file for + inititalize appropriate vars
    # format helps put dyanmic values in placeholder{} declared in working vars
    if browser_choice == 0: 
        crx_url = chrome_crx_url.format(extensionid=crx_guid)
        crx_page_url = chrome_crx_page_url.format(extensionid=crx_guid)
    elif browser_choice == 1: 
        crx_url = edge_crx_url.format(extensionid=crx_guid)
        crx_page_url = edge_crx_page_url.format(extensionid=crx_guid)
    else:
        print("Please select compatible browser")
        exit()
    
    print("Checking for extension in webstore....")
    # check if crx is present in webstore
    crx_file_req = requests.get(crx_url, allow_redirects=True)
    if (crx_file_req.status_code != 200):
        print("No such extenxtion exist on webstore")
        exit()

    # find crx name from webstore page + initialize name for file to be stored on disk
    # extarct page content as text to run regex filter(s)
    crx_page_content = requests.get(crx_page_url,allow_redirects=True).text
    # group(1) only matches the text, leaves out tags 
    match = title_pattern.search(crx_page_content)
    # eliminate dangerous characters n whitespaces
    safe_match = re.sub(sanitizer_pattern,"-",match.group(1))
    print(f"Extension Found: {safe_match}")

    #strftime to provide timestamp
    crx_file = crx_guid + "_" + safe_match + "_" + time.strftime("%Y%m%d-%H%M%S") + ".crx"

    upload_file = os.path.join(crx_dir,crx_file)
    unzip_crx_file = crx_file.replace(".crx","")
    retire_scan_file = os.path.join(unzip_crx_dir, unzip_crx_file)

    # write request content in raw bytes to create crx on disk
    with open(upload_file, 'wb') as file:
        file.write(crx_file_req.content)

    # free up memory
    del crx_page_content
    del crx_file_req

    return upload_file, unzip_crx_file, retire_scan_file

# check file size
def file_size(file_path):
    if os.path.isfile(file_path):
        file_info = os.stat(file_path).st_size
        file_size_mb = file_info/1048576                    # 1024 (kb) * 1024 for mb
        print(f"File Size(MB): {file_size_mb:.2f}")         # MB with 2 point decimal precision

        return file_info

# permission checker + risk analysis
def permission_checker(retire_scan_file):
  high_risk = ["<all_urls>", "app.window.fullscreen.overrideEsc", "audioCapture", "browsingData", "content_security_policy", "contentSettings", "copresence", "debugger", "declarativeNetRequest", "declarativeWebRequest", "downloads", "downloads.open", "experimental", "hid", "history", "nativeMessaging", "pageCapture", "privacy", "proxy", "socket", "*://*/*", "tabCapture", "tabs", "unsafe-eval", "usb", "usbDevices", "videoCapture", "vpnProvider", "web_accessible_resources", "webNavigation"]
  medium_risk = ["activeTab", "bookmarks", "clipboardRead", "clipboardWrite", "contextMenus", "cookies", "desktopCapture", "downloads", "fileSystem", "fileSystem.directory", "fileSystem.retainEntries", "fileSystem.write", "fileSystem.writeDirectory", "geolocation", "identity", "identity.email", "management", "processes", "sessions", "syncFileSystem", "system.storage", "topSites", "tts", "webRequest", "webRequestBlocking"]
  low_risk = ["accessibilityFeatures.modify", "accessibilityFeatures.read", "alarms", "alwaysOnTopWindows", "app.window.alpha", "app.window.alwaysOnTop", "app.window.fullscreen", "app.window.shape", "background", "certificateProvider", "declarativeContent", "documentScan", "enterprise.deviceAttributes", "enterprise.hardwarePlatform", "enterprise.platformKeys", "externally_connectable", "fileBrowserHandler", "fileSystemProvider", "fontSettings", "gcm", "homepage_url", "idle", "mediaGalleries", "networking.config", "notifications", "overrideEscFullscreen", "platformKeys", "power", "printerProvider", "signedInDevices", "storage", "system.memory", "system.cpu", "system.display", "ttsEngine", "unlimitedStorage", "wallpaper", "webview"]
  
  # Manifest PATH for extension
  manifest = retire_scan_file+"\\manifest.json"
  manifest_data = None

  # load data from manifest
  with open(manifest, 'r') as manifest_json:
      manifest_data = json.load(manifest_json)

  critical_permission, high_permission, medium_permission, low_permission = ([] for i in range(4))
  
  # check if host permissions exist in manifest
  if "host_permissions" in manifest_data: critical_permission.append("host_permission")

  # check if permissions exist in manifest
  if "permissions" in manifest_data:
    crx_permissions = manifest_data["permissions"]
    
    for permission in crx_permissions:
        if permission in high_risk:
            high_permission.append(permission)
            
        elif permission in medium_risk:
            medium_permission.append(permission)
            
        elif permission in low_risk:
            low_permission.append(permission)

  # Check for Content Security Policy if exists
  if "content_security_policy" in manifest_data: print("\nContent Security Policy: Present")
  else: print("\nContent Security Policy: Not Present")
  
  # Risk Analysis Report
  print(f"\nRisk Analysis:\nCritical Risk: {', '.join(critical_permission)}\nHigh Risk: {', '.join(high_permission)}\nMedium Risk: {', '.join(medium_permission)}\nLow Risk: {', '.join(low_permission)}")

  # free memory
  del manifest_data

# hash seraching for file via Virustotal
def vt_hash_search(crx_sha256_hash=None, api_key=None):
   url = "https://www.virustotal.com/api/v3/files/" + crx_sha256_hash
   
   headers = {
      "accept": "application/json",
      "x-apikey": api_key
  }
   
   vt_sha256_search = requests.get(url, headers=headers)
   return vt_sha256_search


# file scanner for malware via VirusTotal
def vt_scan(upload_file=None, api_key=None):
  vt_crx = upload_file.removeprefix("C:\\Users\\A0831400\\Downloads\\crx-scanner\\zips")
  
  # request to upload file
  scan_files = { "file": (vt_crx, open(upload_file, "rb"), "application/x-zip-compressed") }
  headers = {
      "accept": "application/json",
      "x-apikey": api_key
  }

  # Check for Big Files (VirusTotal implements diff upload url for files > 32mb and <= 650mb for analysis)
  crx_size = file_size(upload_file)
  if crx_size >= 33554432 and crx_size <= 681574400:
    big_file_url = "https://www.virustotal.com/api/v3/files/upload_url"
    response = requests.get(big_file_url, headers=headers)
    url_upload = response.json()["data"]
  elif crx_size < 33554432:
    # standard file upload url
    url_upload = "https://www.virustotal.com/api/v3/files"
  else:
      print("size too big, cannot move forward")
      exit()

  scan_response = requests.post(url_upload, files=scan_files, headers=headers).json()

  analysis_id = scan_response["data"]["id"]
  url_result = scan_response["data"]["links"]["self"]

  print(f"VT AnalysisID: {analysis_id}")

  # construct url for analysis
#   check_result = "https://www.virustotal.com/api/v3/analyses/"
#   url_result = check_result + quote(analysis_id, safe='')
  
  # get analysis response
  count = 0
  initial_req = 0
  while True:
    if initial_req == 0:
       time.sleep(10.0)
       initial_req += 1
    
    analysis_result = requests.get(url_result, headers=headers).json()
    if (analysis_result["data"]["attributes"]["status"] == "completed"): 
        break
    
    time.sleep(20.0)
    count += 1

  print(count+2)
  return analysis_result

# PROMPT
banner = """
   ____ ____  __  __  ____                                  
  / ___|  _ \\ \\ \\/ / / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |   | |_) | \\  /  \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
 | |___|  _ <  /  \\   ___) | (_| (_| | | | | | | |  __/ |   
  \\____|_| \\_\\/_/\\_\\ |____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
                                                           
"""

print(f"{banner}\nNOTE: This tool only accepts guids from Chrome and Edge extension webstores.")

# reading api key
api_key = None
with open("VT API Key.txt", "r") as key_file:
    api_key = key_file.readline()

# sanitized user input
browser_choice = int(input("Select browser [Chrome(0) | Edge(1)]: "))
crx_guid = input("Enter crx guid: ")
crx_guid = re.sub(PATTERN_DANGER_CHAR,"",crx_guid)

# call file paths to perform malware, risk and sbom analysis
upload_file, unzip_crx_file, retire_scan_file = crx_downloader(browser_choice, crx_guid)

print("Starting Analysis....")

# calculate sha256
crx_sha256_hash = crx_hash(upload_file)
print(f"SHA256 Hash: {crx_sha256_hash.upper()}")

# Extarct crx zip and prepare for retire scan
#print("Extracting archive for retire scan")
subprocess.run(f"7z x {upload_file} -o{unzip_crx_file} -r", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
subprocess.run(["powershell","-c", "Move-Item", f"{unzip_crx_file}", "-Destination", f"'{retire_scan_file}'"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

# Risk Rating based on permilssions
permission_checker(retire_scan_file)

#retire scan
print("\nRunning Retire scan:")
subprocess.run(f"retire --path {retire_scan_file}", shell=True)
# subprocess.run(f"retire --jsrepo C:\\Users\\A0831400\\Downloads\\crx-scanner-work\\jsrepository-v4.json --path {retire_scan_file}", shell=True)

# hash/malware scan
vt_hash_search_result = vt_hash_search(crx_sha256_hash, api_key)

if(vt_hash_search_result.status_code != 200):
   print("Hash Scan returned no results, moving to full scan.")
   vt_scan_result = vt_scan(upload_file, api_key)["data"]["attributes"]["stats"]
   print(f"Virustotal Scan Summary:\n{vt_scan_result}")
else:
   print(f"VT Hash Scan Summary:\n{vt_hash_search_result.json()["data"]["attributes"]["last_analysis_stats"]}")
