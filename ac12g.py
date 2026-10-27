import argparse
import json
import socket
import subprocess
import requests
import urllib3
import xml.etree.ElementTree as ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def send_soap(target_ip, control_path, action_name, service_type, body_content=""):
    # As requisições SOAP respondem na porta UPnP 1900 nos endpoints (/ipc, /ifc, /l3f)
    url = f"http://{target_ip}:1900{control_path}"
    envelope = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action_name} xmlns:u="{service_type}">
      {body_content}
    </u:{action_name}>
  </s:Body>
</s:Envelope>"""

    headers = {
        "Content-Type": "text/xml; charset=\"utf-8\"",
        "SOAPAction": f"\"{service_type}#{action_name}\""
    }

    try:
        response = requests.post(url, data=envelope, headers=headers, timeout=4, verify=False)
        return response.status_code, response.text
    except Exception as e:
        return 500, str(e)

def parse_all_tags(xml_data):
    results = {}
    try:
        root = ET.fromstring(xml_data)
        for elem in root.iter():
            tag_name = elem.tag.split('}')[-1]
            if elem.text and elem.text.strip():
                results[tag_name] = elem.text.strip()
    except:
        pass
    return results

def run_full_audit(target_ip):
    print(f"\n[*] Iniciando auditoria completa no alvo: {target_ip}...")
    report_data = {
        "target": target_ip,
        "actions": {},
        "port_mappings": []
    }

    targets = [
        {"path": "/ipc", "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "action": "GetStatusInfo"},
        {"path": "/ipc", "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "action": "GetExternalIPAddress"},
        {"path": "/ipc", "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "action": "GetNATRSIPStatus"},
        {"path": "/ifc", "service": "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1", "action": "GetCommonLinkProperties"},
        {"path": "/ifc", "service": "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1", "action": "GetTotalBytesSent"},
        {"path": "/ifc", "service": "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1", "action": "GetTotalBytesReceived"},
        {"path": "/l3f", "service": "urn:schemas-upnp-org:service:Layer3Forwarding:1", "action": "GetDefaultConnectionService"}
    ]

    for item in targets:
        print(f"\n[*] Testando Ação: [{item['action']}] em ({item['path']})...")
        status, resp = send_soap(target_ip, item['path'], item['action'], item['service'])
        
        if status == 200:
            print(f"    [+] Sucesso! (HTTP 200)")
            parsed_data = parse_all_tags(resp)
            report_data["actions"][item['action']] = parsed_data
            for k, v in parsed_data.items():
                if k not in ["Envelope", "Body", item['action'] + "Response"]:
                    print(f"        -> {k}: {v}")
        else:
            print(f"    [-] Indisponível ou recusado (Status: {status})")
            report_data["actions"][item['action']] = {"status": status}

    # Port Mappings
    mappings = []
    for index in range(5):
        body = f"<NewPortMappingIndex>{index}</NewPortMappingIndex>"
        status, resp = send_soap(target_ip, "/ipc", "GetGenericPortMappingEntry", "urn:schemas-upnp-org:service:WANIPConnection:1", body)
        if status == 200 and "NewPortMappingDescription" in resp:
            data = parse_all_tags(resp)
            mappings.append(data)
        else:
            break

    if mappings:
        print(f"\n    [+] Encontradas {len(mappings)} regras de porta ativas:")
        for m in mappings:
            print(f"        -> Porta Interna: {m.get('NewInternalPort')} | Externa: {m.get('NewExternalPort')} | IP: {m.get('NewInternalClient')}")
        report_data["port_mappings"] = mappings
    else:
        print("\n    [-] Nenhuma regra de redirecionamento de porta ativa.")

    filename = f"report_{target_ip.replace('.', '_')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)
    print(f"\n[+] Relatório exportado com sucesso para: {filename}")

def run_arp_scan():
    print("\n[*] Coletando dispositivos na tabela ARP local...")
    try:
        arp_result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        if arp_result.returncode == 0 and arp_result.stdout.strip():
            for line in arp_result.stdout.splitlines():
                print(f"    {line}")
        else:
            print("    [-] Tabela ARP vazia ou indisponível.")
    except Exception as e:
        print(f"    [-] Erro ao executar arp -a: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auditor Interativo UPnP/SOAP")
    parser.add_argument("-t", "--target", default="192.168.1.1", help="Endereço IP do roteador (padrão: 192.168.1.1)")
    args = parser.parse_args()

    target_ip = args.target

    while True:
        print("\n" + "=======================================================")
        print("       AUDITOR DE SEGURANÇA UPnP / MERCUSYS AC12G      ")
        print("=======================================================")
        print(f" Alvo atual configurado: {target_ip}:1900 (UPnP)")
        print("-------------------------------------------------------")
        print(" [1] Executar Auditoria Completa (SOAP + Port Mappings + JSON)")
        print(" [2] Consultar Status e Uptime da WAN (/ipc)")
        print(" [3] Consultar IP Externo WAN (/ipc)")
        print(" [4] Verificar Regras de Port Forwarding (/ipc)")
        print(" [5] Listar Dispositivos Conectados na LAN (Tabela ARP)")
        print(" [6] Alterar IP do Alvo")
        print(" [0] Sair")
        print("=======================================================")

        choice = input("Escolha uma opção: ").strip()

        if choice == "1":
            run_full_audit(target_ip)
        elif choice == "2":
            status, resp = send_soap(target_ip, "/ipc", "GetStatusInfo", "urn:schemas-upnp-org:service:WANIPConnection:1")
            if status == 200:
                print("\n[+] Resposta GetStatusInfo:")
                for k, v in parse_all_tags(resp).items():
                    print(f"    -> {k}: {v}")
            else:
                print(f"\n[-] Falha (Status: {status})")
        elif choice == "3":
            status, resp = send_soap(target_ip, "/ipc", "GetExternalIPAddress", "urn:schemas-upnp-org:service:WANIPConnection:1")
            if status == 200:
                print("\n[+] Resposta GetExternalIPAddress:")
                for k, v in parse_all_tags(resp).items():
                    print(f"    -> {k}: {v}")
            else:
                print(f"\n[-] Falha (Status: {status})")
        elif choice == "4":
            print("\n[*] Verificando Port Forwarding...")
            found = False
            for idx in range(5):
                body = f"<NewPortMappingIndex>{idx}</NewPortMappingIndex>"
                status, resp = send_soap(target_ip, "/ipc", "GetGenericPortMappingEntry", "urn:schemas-upnp-org:service:WANIPConnection:1", body)
                if status == 200 and "NewPortMappingDescription" in resp:
                    found = True
                    m = parse_all_tags(resp)
                    print(f"    -> Regra {idx}: Porta Externa {m.get('NewExternalPort')} -> IP Interno {m.get('NewInternalClient')}")
            if not found:
                print("    [-] Nenhuma regra encontrada.")
        elif choice == "5":
            run_arp_scan()
        elif choice == "6":
            new_ip = input("Digite o novo IP do roteador (ex: 192.168.1.1): ").strip()
            if new_ip:
                target_ip = new_ip
                print(f"[+] Alvo alterado com sucesso para: {target_ip}")
            else:
                print("[!] IP inválido. O alvo anterior foi mantido.")
        elif choice == "0":
            print("\nEncerrando o auditor. Até logo!")
            break
        else:
            print("\n[!] Opção inválida! Tente novamente.")