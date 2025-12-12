import os
import json
import requests
import hashlib
import yaml
import pefile
import re  # Importamos Regex para ler o nome do arquivo
from pathlib import Path

BASE_PATH = "manifests"
TEMP_FILE = "temp_installer.exe"

# Função para extrair versão do NOME DO ARQUIVO (Ex: NVIDIA_app_v11.0.5.420.exe)
def extrair_versao_url(url):
    # Procura padrões como v1.2.3.4 ou 1.2.3.4 no link final
    padrao = r"v?(\d+\.\d+\.\d+\.\d+)"
    match = re.search(padrao, url)
    if match:
        return match.group(1)
    return None

def obter_versao_exe(path):
    try:
        pe = pefile.PE(path)
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            ver = pe.VS_FIXEDFILEINFO[0]
            # Tenta pegar versão binária
            versao = f"{ver.FileVersionMS >> 16}.{ver.FileVersionMS & 0xFFFF}.{ver.FileVersionLS >> 16}.{ver.FileVersionLS & 0xFFFF}"
            if versao != "0.0.0.0":
                return versao
    except Exception:
        pass
    return None

def criar_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def processar_app(app):
    print(f"--- Processando: {app['name']} ---")
    
    # URL Inicial
    url_para_baixar = app["url"]
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        # allow_redirects=True é crucial para pegar o link final da NVIDIA
        r = requests.get(url_para_baixar, stream=True, headers=headers, allow_redirects=True)
        r.raise_for_status()

        # PEGA A URL FINAL REAL (Aquela que tem o numero da versao)
        final_url = r.url
        print(f"Link final detectado: {final_url}")

        with open(TEMP_FILE, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    except Exception as e:
        print(f"ERRO FATAL ao baixar: {e}")
        return

    # --- ESTRATÉGIA DE VERSÃO ---
    versao = None
    
    # 1. Tenta ler do arquivo .exe (Metadados)
    versao = obter_versao_exe(TEMP_FILE)
    
    # 2. Se falhar, tenta ler da URL FINAL (Regex)
    if not versao or versao == "0.0.0.0":
        print("Aviso: Leitura interna falhou. Tentando extrair do nome do arquivo...")
        versao = extrair_versao_url(final_url)

    # 3. Fallback Manual
    if not versao:
        if "manualVersion" in app:
            versao = app["manualVersion"]
        else:
            versao = "0.0.0.1" # Último recurso
            
    print(f"VERSÃO FINAL DECIDIDA: {versao}")

    # Criação das pastas
    publisher = app['publisher'].replace(" ", "")
    name = app['name'].replace(" ", "")
    path_dir = f"{BASE_PATH}/{publisher[0].lower()}/{publisher}/{name}/{versao}"
    Path(path_dir).mkdir(parents=True, exist_ok=True)
    
    # Hash
    h = hashlib.sha256()
    with open(TEMP_FILE, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    hash_str = h.hexdigest()

    # Gera Manifests
    base_id = app['id']
    
    # Main
    criar_yaml(f"{path_dir}/{base_id}.yaml", {
        "PackageIdentifier": base_id,
        "PackageVersion": versao,
        "PackageLocale": "en-US",
        "Publisher": app["publisher"],
        "PackageName": app["name"],
        "ManifestType": "version",
        "ManifestVersion": "1.4.0"
    })

    # Installer
    criar_yaml(f"{path_dir}/{base_id}.installer.yaml", {
        "PackageIdentifier": base_id,
        "PackageVersion": versao,
        "InstallerType": "exe",
        "Installers": [{
            "Architecture": "x64",
            "InstallerUrl": final_url, # Usa o link direto resolvido
            "InstallerSha256": hash_str
        }],
        "ManifestType": "installer",
        "ManifestVersion": "1.4.0"
    })
    
    # Locale
    criar_yaml(f"{path_dir}/{base_id}.locale.en-US.yaml", {
        "PackageIdentifier": base_id,
        "PackageVersion": versao,
        "PackageLocale": "en-US",
        "Publisher": app["publisher"],
        "PackageName": app["name"],
        "ShortDescription": app["name"],
        "ManifestType": "defaultLocale",
        "ManifestVersion": "1.4.0"
    })

    if os.path.exists(TEMP_FILE): os.remove(TEMP_FILE)
    print(f"Sucesso! Pacote gerado em {path_dir}")

def main():
    if not os.path.exists("scripts/apps.json"):
        return
    with open("scripts/apps.json", "r", encoding="utf-8") as f:
        apps = json.load(f)
    for app in apps:
        processar_app(app)

if __name__ == "__main__":
    main()
