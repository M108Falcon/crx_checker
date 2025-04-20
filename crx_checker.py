# -------------------------------------
# Interpreter: Python
# Version: 20241119.4
# Function: Assess browser extensions for malware, risks and sbom vulnerabilities
# Output: stdout
# Created by M108Falcon
# -------------------------------------

import os
import requests
from urllib.parse import quote # url encode
import subprocess
import json

# check file size
def file_size(file_path):
    if os.path.isfile(file_path):
        file_info = os.stat(file_path)
        return file_info.st_size

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
  manifest_json.close()

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

# file scanner for malware via VirusTotal
def vt_scan(upload_file, api_key):
  # request to upload file
  scan_files = { "file": (vt_crx, open(upload_file, "rb"), "application/x-zip-compressed") }
  headers = {
      "accept": "application/json",
      "x-apikey": api_key
  }

  # Check for Big Files (VirusTotal implements diff upload url for files > 32mb for analysis)
  crx_size = file_size(upload_file)
  if crx_size >= 33554432:
    big_file_url = "https://www.virustotal.com/api/v3/files/upload_url"
    response = requests.get(big_file_url, headers=headers)
    url_upload = response.json()["data"]
  else:
    # standard file upload url
    url_upload = "https://www.virustotal.com/api/v3/files"

  scan_response = requests.post(url_upload, files=scan_files, headers=headers)

  analysis_data = scan_response.json()
  analysis_id = analysis_data["data"]["id"]

  # check url analysis
  check_result = "https://www.virustotal.com/api/v3/analyses/"
  url_result = check_result + quote(analysis_id, safe='')
  
  # get analysis response
  result_response = requests.get(url_result, headers=headers)
  return(result_response.json())

# PROMPT
banner = """
   ____ ____  __  __  ____                                  
  / ___|  _ \ \ \/ / / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |   | |_) | \  /  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |___|  _ <  /  \   ___) | (_| (_| | | | | | | |  __/ |   
  \____|_| \_\/_/\_\ |____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                            
"""

print(f"{banner}\nNOTE: Please only upload zip files for downloaded extensions and not any data containing company confidential information.")

# reading api key
key_file = open("VT API Key.txt", "r")
api_key = key_file.readline()
key_file.close()

#VT scanner vars
vt_crx = input("Enter the name of zipped crx: ")
crx_dir = "D:\\Pentest\\crx_checker\\zips"
unzip_crx = vt_crx.replace(".zip","")
unzip_crx_dir = "D:\\Pentest\\crx_checker\\unzipped_crxs"
upload_file = os.path.join(crx_dir,vt_crx)
retire_scan_file = os.path.join(unzip_crx_dir, unzip_crx)

# malware scan
vt_result = vt_scan(upload_file, api_key)["data"]["attributes"]["stats"]
print(f"Virustotal Scan Summary:\n{vt_result}")

# Extarct crx zip and prepare for retire scan
#print("Extracting archive for retire scan")
subprocess.run(f"7z x {upload_file} -o{unzip_crx} -r", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
subprocess.run(["powershell","-c", "Move-Item", f"{unzip_crx}", "-Destination", f"'{retire_scan_file}'"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

# Risk Rating based on permilssions
permission_checker(retire_scan_file)

#retire scan
print("\nRunning Retire scan:")
subprocess.run(f"retire --path {retire_scan_file}", shell=True)

# use below line if in corporate environment
# subprocess.run(f"retire --jsrepo C:\\Users\\A0831400\\Downloads\\retire\\jsrepository-v4.json --path {retire_scan_file}", shell=True)