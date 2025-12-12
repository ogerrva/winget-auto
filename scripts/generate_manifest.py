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

def baixar_arquivo(url, destino):
    print(f"Baixando: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        r = requests.get(url, stream=True, headers=headers, allow_redirects=True)
        r.raise_for_status()
        
        # Verifica se baixou HTML (login) em vez de EXE
        if 'text/html' in r.headers.get('content-type', ''):
            print("ERRO: O link retornou uma página web (provavelmente login/bloqueio).")
            return False

        with open(destino, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        print(f"ERRO ao baixar: {e}")
        return False

def obter_versao_exe(path):
    pe = None
    try:
        pe = pefile.PE(path)
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            ver = pe.VS_FIXEDFILEINFO[0]
            versao = f"{ver.FileVersionMS >> 16}.{ver.FileVersionMS & 0xFFFF}.{ver.FileVersionLS >> 16}.{ver.FileVersionLS & 0xFFFF}"
            if versao != "0.0.0.0":
                return versao
    except Exception:
        pass
    finally:
        # CORREÇÃO CRÍTICA: Fecha o arquivo para liberar o Windows
        if pe:
            pe.close()
    return None

def criar_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def processar_app(app):
    print(f"--- Processando: {app['name']} ---")
    
    if not baixar_arquivo(app["url"], TEMP_FILE):
        return

    # 1. Tenta ler versão interna
    versao = obter_versao_exe(TEMP_FILE)
    
    # 2. Se falhar, tenta extrair do Link (ex: ...v11.0.5.420.exe)
    if not versao or versao == "0.0.0.0":
        print("Leitura interna falhou/genérica. Tentando extrair do link...")
        match = re.search(r"v?(\d+\.\d+\.\d+\.\d+)", app["url"])
        if match:
            versao = match.group(1)
    
    # 3. Fallback Manual
    if not versao:
        versao = app.get("manualVersion", "0.0.0.1")

    print(f"VERSÃO FINAL: {versao}")

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

    base_id = app['id']
    
    # Gera os 3 arquivos YAML
    criar_yaml(f"{path_dir}/{base_id}.yaml", {
        "PackageIdentifier": base_id,
        "PackageVersion": versao,
        "PackageLocale": "en-US",
        "Publisher": app["publisher"],
        "PackageName": app["name"],
        "ManifestType": "version",
        "ManifestVersion": "1.4.0"
    })

    criar_yaml(f"{path_dir}/{base_id}.installer.yaml", {
        "PackageIdentifier": base_id,
        "PackageVersion": versao,
        "InstallerType": "exe",
        "Installers": [{
            "Architecture": "x64",
            "InstallerUrl": app["url"],
            "InstallerSha256": hash_str
        }],
        "ManifestType": "installer",
        "ManifestVersion": "1.4.0"
    })
    
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

    # Limpeza segura
    if os.path.exists(TEMP_FILE):
        try:
            os.remove(TEMP_FILE)
            print("Limpeza concluída.")
        except PermissionError:
            print("AVISO: Não foi possível deletar o arquivo temporário (ainda em uso), mas o manifest foi gerado.")

def main():
    if not os.path.exists("scripts/apps.json"): return
    with open("scripts/apps.json", "r", encoding="utf-8") as f:
        apps = json.load(f)
    for app in apps:
        processar_app(app)

if __name__ == "__main__":
    main()
