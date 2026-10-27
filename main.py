import requests
import urllib3
import xml.etree.ElementTree as ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_IP = "192.168.0.1"
UPNP_PORT = 1900
BASE_URL = f"http://{TARGET_IP}:{UPNP_PORT}"

def send_soap(control_path, action_name, service_type, body_content=""):
    url = f"{BASE_URL}{control_path}"
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

if __name__ == "__main__":
    print("=" * 70)
    print(" Auditor Avançado de UPnP / SOAP - Incluindo Inventário de Clientes")
    print("=" * 70)

    # Lista ampliada de alvos incluindo endpoints e serviços de LAN/Hosts
    targets = [
        # WAN / Status Geral
        {"path": "/ipc", "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "action": "GetStatusInfo", "body": ""},
        {"path": "/ipc", "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "action": "GetExternalIPAddress", "body": ""},
        {"path": "/ipc", "service": "urn:schemas-upnp-org:service:WANIPConnection:1", "action": "GetNATRSIPStatus", "body": ""},
        
        # Link e Tráfego WAN
        {"path": "/ifc", "service": "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1", "action": "GetCommonLinkProperties", "body": ""},
        {"path": "/ifc", "service": "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1", "action": "GetTotalBytesSent", "body": ""},
        {"path": "/ifc", "service": "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1", "action": "GetTotalBytesReceived", "body": ""},

        # Layer 3 / LAN Hosts (Tentativa de varredura de hosts conectados)
        {"path": "/l3f", "service": "urn:schemas-upnp-org:service:Layer3Forwarding:1", "action": "GetDefaultConnectionService", "body": ""},
    ]

    for item in targets:
        print(f"\n[*] Testando Ação: [{item['action']}] em Endpoint ({item['path']})...")
        status, resp = send_soap(item['path'], item['action'], item['service'], item['body'])
        
        if status == 200:
            print(f"    [+] Sucesso! (HTTP 200)")
            parsed_data = parse_all_tags(resp)
            for k, v in parsed_data.items():
                if k not in ["Envelope", "Body", item['action'] + "Response"]:
                    print(f"        -> {k}: {v}")
        else:
            print(f"    [-] Indisponível ou recusado (Status: {status})")

    # Tentativa extra: varredura direta via ARP scan na sub-rede local para listar dispositivos ativos
    print(f"\n[*] Executando varredura rápida de dispositivos na LAN (ARP / Host Discovery)...")
    import subprocess
    try:
        # Roda um comando ip neighbor ou arp -a integrado para complementar o inventário
        arp_result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        if arp_result.returncode == 0 and arp_result.stdout.strip():
            print("    [+] Dispositivos detectados na tabela ARP local:")
            for line in arp_result.stdout.splitlines():
                print(f"        {line}")
        else:
            print("    [-] Tabela ARP vazia ou comando indisponível.")
    except Exception as e:
        print(f"    [-] Não foi possível executar o mapeamento ARP local: {e}")

    print("\n" + "=" * 70)
    print(" Auditoria e Inventário Concluídos.")
    print("=" * 70)