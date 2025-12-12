import os
import json
import requests
import hashlib
import yaml
import pefile
import re
from pathlib import Path

BASE_PATH = "manifests"
TEMP_FILE = "temp_installer.exe"

def caçar_link_real(url_inicial, padrao_regex):
    print(f"   -> Caçando link na página: {url_inicial}")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
        r = requests.get(url_inicial, headers=headers, timeout=15)
        r.raise_for_status()
        
        # Procura no HTML da página qualquer link que bata com o padrão
        # Exemplo: href="https://...NVIDIA_app_v11.0.5.420.exe"
        match = re.search(padrao_regex, r.text)
        if match:
            link_encontrado = match.group(1)
            # Se o link for relativo (/download/...), coloca o dominio
            if link_encontrado.startswith("/"):
                # Simplificação: assume que o usuario vai por o link completo no regex se precisar
                pass 
            print(f"   -> LINK ENCONTRADO: {link_encontrado}")
            return link_encontrado
    except Exception as e:
        print(f"   -> Erro ao caçar link: {e}")
    
    return None

def obter_versao_exe(path):
    try:
        pe = pefile.PE(path)
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            ver = pe.VS_FIXEDFILEINFO[0]
            versao = f"{ver.FileVersionMS >> 16}.{ver.FileVersionMS & 0xFFFF}.{ver.FileVersionLS >> 16}.{ver.FileVersionLS & 0xFFFF}"
            if versao != "0.0.0.0":
                return versao
    except:
        pass
    return None

def criar_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def processar_app(app):
    print(f"--- Processando: {app['name']} ---")
    
    url_final = app["url"]
    
    # SE TIVER O CAMPO 'SEARCH_PAGE', ativamos o modo Caçador
    if "search_page" in app:
        novo_link = caçar_link_real(app["search_page"], app["search_regex"])
        if novo_link:
            url_final = novo_link
        else:
            print("   -> AVISO: Não achei link novo. Usando URL padrão do JSON.")

    # Baixar
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        r = requests.get(url_final, stream=True, headers=headers, allow_redirects=True)
        r.raise_for_status()
        
        # Verifica se baixou um HTML (erro de login) em vez de EXE
        content_type = r.headers.get('content-type', '')
        if 'text/html' in content_type:
            print("ERRO FATAL: O link baixou uma página web (provavelmente login) em vez do arquivo .exe.")
            print("Verifique se o link 'go.nvidia' está bloqueando bots.")
            return

        with open(TEMP_FILE, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    except Exception as e:
        print(f"ERRO ao baixar: {e}")
        return

    # Versão
    versao = obter_versao_exe(TEMP_FILE)
    
    # Fallback: Tenta pegar do nome do arquivo (NVIDIA_app_v11.0.5.420.exe)
    if not versao:
        match_nome = re.search(r"v?(\d+\.\d+\.\d+\.\d+)", url_final)
        if match_nome:
            versao = match_nome.group(1)

    if not versao:
        versao = app.get("manualVersion", "0.0.0.1")

    print(f"VERSÃO DETECTADA: {versao}")

    # Criação dos arquivos (igual antes)
    publisher = app['publisher'].replace(" ", "")
    name = app['name'].replace(" ", "")
    path_dir = f"{BASE_PATH}/{publisher[0].lower()}/{publisher}/{name}/{versao}"
    Path(path_dir).mkdir(parents=True, exist_ok=True)
    
    h = hashlib.sha256()
    with open(TEMP_FILE, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    hash_str = h.hexdigest()

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
            "InstallerUrl": url_final, # Usa o link descoberto
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
    print("Sucesso!")

def main():
    if not os.path.exists("scripts/apps.json"): return
    with open("scripts/apps.json", "r", encoding="utf-8") as f:
        apps = json.load(f)
    for app in apps:
        processar_app(app)

if __name__ == "__main__":
    main()
