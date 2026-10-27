# 👋🏻 Leonardo de Moura Fuseti

Estudante de Defesa Cibernetica no Polo Estacio Piumhi MG . Formação tecnica em Tecnico em Redes de Computadores no IFMG Bambui MG , intusiasta na programação gostando muito de Python e evoluindo dia a dia .

### Conecte-se comigo

[![Perfil DIO](https://img.shields.io/badge/-Meu%20Perfil%20na%20DIO-30A3DC?style=for-the-badge)](https://www.dio.me/users/mourafuseti)
[![E-mail](https://img.shields.io/badge/-Email-000?style=for-the-badge&logo=microsoft-outlook&logoColor=E94D5F)](mailto:mourafuseti@gmail.com)
[![LinkedIn](https://img.shields.io/badge/-LinkedIn-000?style=for-the-badge&logo=linkedin&logoColor=30A3DC)](https://www.linkedin.com/in/leonardo-moura-fuseti-4052b0359/)
[![Livro](https://img.shields.io/badge/Livro-Python_do_Básico_ao_Avançado-E94D5F?style=for-the-badge&logo=read-the-docs&logoColor=white)](https://github.com/mourafuseti)

### Habilidades

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![OpenCV](https://img.shields.io/badge/OpenCV-5C3EE8?style=for-the-badge&logo=opencv&logoColor=white)
![HTML](https://img.shields.io/badge/HTML-000?style=for-the-badge&logo=html5&logoColor=30A3DC)
![CSS3](https://img.shields.io/badge/CSS3-000?style=for-the-badge&logo=css3&logoColor=E94D5F)
![JavaScript](https://img.shields.io/badge/JavaScript-000?style=for-the-badge&logo=javascript&logoColor=F0DB4F)
![Sass](https://img.shields.io/badge/SASS-000?style=for-the-badge&logo=sass&logoColor=CD6799)
![Bootstrap](https://img.shields.io/badge/bootstrap-000?style=for-the-badge&logo=bootstrap&logoColor=553C7B)
[![Git](https://img.shields.io/badge/Git-000?style=for-the-badge&logo=git&logoColor=E94D5F)](https://git-scm.com/doc)
[![GitHub](https://img.shields.io/badge/GitHub-000?style=for-the-badge&logo=github&logoColor=30A3DC)](https://docs.github.com/)

### 📊 GitHub Stats

<p align="left">
  <img src="https://github-readme-stats-sigma-five.vercel.app/api?username=mourafuseti&show_icons=true&theme=tokyonight&bg_color=000&border_color=30A3DC&title_color=E94D5F&text_color=FFF" alt="GitHub Stats" />
</p>

# Lab Cibersegurança: Auditoria de Roteadores & UPnP (Mercusys AC12G)

Projeto de laboratório prático voltado para **Análise de Vulnerabilidades, Enumeração de Rede e Testes de Protocolos de Gerenciamento (UPnP/SOAP)** em dispositivos embarcados (Firmware VxWorks).

---

## 🛠️ Sobre o Projeto
Este repositório contém scripts em Python desenvolvidos para auditar a superfície de ataque de roteadores residenciais locais (com foco no modelo **Mercusys AC12G V1**). O projeto simula o fluxo de um pentest/auditoria de infraestrutura de rede, desde a descoberta de hosts até a extração de dados gerenciais via chamadas SOAP sem autenticação.

## 🚀 Funcionalidades do Script (`main.py`)
* **Descoberta de Serviços UPnP:** Conexão TCP na porta 1900 e envio de pacotes SSDP M-SEARCH (UDP) para mapeamento de dispositivos.
* **Extrator de Schema (IGD):** Download e análise automatizada do arquivo descritivo `igd.xml`.
* **Mapeamento de Sub-schemas:** Varredura e extração de endpoints de serviço (`/l3f.xml`, `/ifc.xml`, `/ipc.xml`).
* **Requisições SOAP Personalizadas:** Execução de ações automatizadas para extração de informações sensíveis do roteador:
  * `GetStatusInfo` (Extração de Uptime e Status de Conexão).
  * `GetExternalIPAddress` (Consulta de IP WAN).
  * `GetCommonLinkProperties` (Estatísticas de link físico e banda).

---

## 📋 Pré-requisitos
Certifique-se de ter o Python 3 instalado no seu ambiente de laboratório (Kali Linux / Linux), juntamente com a biblioteca `requests`:

```bash
sudo apt update
sudo apt install python3-requests python3-pip -y

🛡️ Aviso Legal (Ethical Disclaimer)

    Este software e as informações contidas neste repositório foram desenvolvidos estritamente para fins educacionais e de pesquisa em laboratório isolado. O autor não apoia nem se responsabiliza por invasões, testes ou explorações em redes ou dispositivos sem a devida autorização explícita do proprietário.

👨‍💻 Autor

Desenvolvido como parte dos estudos práticos de Defesa Cibernética e Engenharia de Software.
