import requests
import os
from opensearchpy import OpenSearch, helpers
from google import genai
from google.genai import types
from time import sleep
from dotenv import load_dotenv

load_dotenv()

WAZUH_INDEXER_AUTH_USER = os.environ.get("WAZUH_INDEXER_AUTH_USER")
WAZUH_INDEXER_AUTH_PASS = os.environ.get("WAZUH_INDEXER_AUTH_PASS")
WAZUH_INDEXER_HOST = os.environ.get("WAZUH_INDEXER_HOST")
WAZUH_INDEXER_PORT = os.environ.get("WAZUH_INDEXER_PORT")

GOOGLEAI_API_KEY = os.environ.get("GOOGLEAI_API_KEY")

opensearch_client = OpenSearch(
    hosts=[{"host": WAZUH_INDEXER_HOST, "port": WAZUH_INDEXER_PORT}],
    http_compress=True,
    http_auth=(WAZUH_INDEXER_AUTH_USER, WAZUH_INDEXER_AUTH_PASS),
    use_ssl=True,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False
)

query = {
    "query": {
        "match_all": {}
    }
}

vulnerabilities = []
# de 1 à 10
machines_risk_score = {
    "ubuntu": 4,
    "DESKTOP-9UKSUMG": 9
}

for doc in helpers.scan(opensearch_client, index="wazuh-states-vulnerabilities-wazuh-server", query=query):
    vulnerabilities.append(doc)

print("#"*50)
print(f"\033[91mTotal de Vulnerabilidades\033[0m: {len(vulnerabilities)}")
print("#"*50)

googleai_client = genai.Client(
    api_key=GOOGLEAI_API_KEY
)

response = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
cisa_kev_list = response.json()["vulnerabilities"]

for vuln in vulnerabilities:
    # if vuln["_source"]["vulnerability"]["id"] == "CVE-2025-33073":

    google_chat = googleai_client.chats.create(
        model="gemini-2.5-flash",
        config=types.GenerateContentConfig(
            system_instruction="Você é um agente que me ajudará a construir um relatório técnico sobre uma vulnerabilidade (CVE)."
        ),
    )

    # Cria o modelo de mensagem gerado por AI
    title = google_chat.send_message(f"Crie um título para a {str(vuln["_source"]["vulnerability"]["id"])} em apenas uma linha de acordo com a descrição: {str(vuln["_source"]["vulnerability"]["description"])}\n\nRestrições: 1. Não gere outro texto a não ser o próprio titulo. 2. Não use o ID da CVE no titulo.")
    summary = google_chat.send_message(f"Faça um resumo curto (3-5 linhas) da {str(vuln["_source"]["vulnerability"]["id"])}. Priorize linguagem técnica para time de infra e segurança.")
    mitigation_steps = google_chat.send_message(f"Faça um resumo (3-5 linhas) de como corrigir ou mitigar a vulnerabilidade {str(vuln["_source"]["vulnerability"]["id"])}.")
    
    # Verifica se a vulnerabilidade tem exploits disponiveis
    available_exploit = False
    for kev in cisa_kev_list:
        if kev["cveID"] == str(vuln["_source"]["vulnerability"]["id"]):
            available_exploit = True
    if available_exploit:
        x1 = 1.0
    else:
        x1 = 0.0

    # Valida o nível de criticitadade do ativo e normaliza
    os_name = vuln["_source"]["agent"]["name"]
    x2 = machines_risk_score[os_name] / 10

    # Normaliza cvss
    x3 = vuln["_source"]["vulnerability"]["score"]["base"] / 10

    # Calcular a prioridade da vulnerabilidade
    calc_priority = x1*0.30 + x2*0.20 + x3*0.50
    calc_priority *= 100

    priority = ""
    if calc_priority >= 85:
        priority = "P0 - Crítica"
    elif calc_priority >= 70 and calc_priority < 85:
        priority = "P1 - Alta"
    elif calc_priority >= 50 and calc_priority < 70:
        priority = "P2 - Média"
    elif calc_priority >= 30 and calc_priority < 50:
        priority = "P3 - Baixa"
    elif calc_priority < 30:
        priority = "P4 - Muito Baixa"

    print("#"*50)
    print(f"\033[91mCVE\033[0m: {vuln["_source"]["vulnerability"]["id"]}")
    print(f"\033[91mTítulo\033[0m: {title.text}")
    print(f"\033[91mResumo\033[0m: {summary.text}")
    print(f"\033[91mMitigação\033[0m: {mitigation_steps.text}")
    print(f"\033[91mSeveridade\033[0m: {vuln["_source"]["vulnerability"]["severity"]} - {vuln["_source"]["vulnerability"]["score"]["base"]}")
    print(f"\033[91mPrioridade\033[0m: {priority}")
    print(f"\033[91mHost afetado\033[0m: {vuln["_source"]["agent"]["name"]} | {vuln["_source"]["host"]["os"]["full"]}")
    print(f"\033[91mPrograma afetado\033[0m: {vuln["_source"]["package"]["name"]}")
    print("#"*50)

    sleep(1)
