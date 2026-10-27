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
        response = requests.post(url, data=envelope, headers=headers, timeout=5, verify=False)
        return response.status_code, response.text
    except Exception as e:
        return 500, str(e)

def parse_tag_text(xml_data, tag_name):
    try:
        # Remove namespaces para facilitar a busca com ElementTree
        root = ET.fromstring(xml_data)
        for elem in root.iter():
            if elem.tag.endswith(tag_name):
                return elem.text
    except:
        pass
    return "Não retornado / Indisponível"

if __name__ == "__main__":
    print("=" * 65)
    print(" Extrator Completo de Informações WAN/LAN via SOAP - Lab")
    print("=" * 65)

    # 1. Consultar Uptime e Status (Endpoint /ipc)
    print("\n[*] Consultando Status e Uptime (/ipc - GetStatusInfo)...")
    status, resp = send_soap("/ipc", "GetStatusInfo", "urn:schemas-upnp-org:service:WANIPConnection:1")
    if status == 200:
        print(f"    [+] Status HTTP: {status}")
        print(f"    [+] Uptime do Equipamento: {parse_tag_text(resp, 'NewUptime')}")
        print(f"    [+] Status de Conexão (Raw/Pointer): {parse_tag_text(resp, 'NewConnectionStatus')}")
        print(f"    [+] Erro de Conexão: {parse_tag_text(resp, 'NewLastConnectionError')}")
    else:
        print("    [-] Falha ao consultar GetStatusInfo")

    # 2. Consultar o IP Externo / WAN (Endpoint /ipc)
    print("\n[*] Consultando Endereço IP da WAN (/ipc - GetExternalIPAddress)...")
    status, resp = send_soap("/ipc", "GetExternalIPAddress", "urn:schemas-upnp-org:service:WANIPConnection:1")
    if status == 200:
        print(f"    [+] Status HTTP: {status}")
        wan_ip = parse_tag_text(resp, 'NewExternalIPAddress')
        print(f"    [+] IP Externo (WAN) Detectado: {wan_ip}")
    else:
        print("    [-] Ação GetExternalIPAddress não suportada ou restrita.")

    # 3. Consultar Propriedades de Link e Taxas (Endpoint /ifc)
    print("\n[*] Consultando Propriedades de Link Common (/ifc - GetCommonLinkProperties)...")
    status, resp = send_soap("/ifc", "GetCommonLinkProperties", "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1")
    if status == 200:
        print(f"    [+] Status HTTP: {status}")
        print(f"    [+] Tipo de Acesso WAN: {parse_tag_text(resp, 'NewWANAccessType')}")
        print(f"    [+] Link Físico Status: {parse_tag_text(resp, 'NewPhysicalLinkStatus')}")
        print(f"    [+] Banda Downstream Máx: {parse_tag_text(resp, 'NewLayer1DownstreamMaxBitRate')}")
    else:
        print("    [-] Falha ao consultar propriedades de link.")

    print("\n" + "=" * 65)