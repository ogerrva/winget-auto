import os
import json
import requests
import hashlib
import yaml
import pefile
from pathlib import Path
import shutil

# Configurações
BASE_PATH = "manifests"
TEMP_FILE = "temp_installer.exe"

def baixar_arquivo(url, destino):
    print(f"Baixando: {url}")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    try:
        r = requests.get(url, stream=True, headers=headers)
        r.raise_for_status()
        with open(destino, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    except Exception as e:
        print(f"Erro ao baixar {url}: {e}")
        return False
    return True

def calcular_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def obter_versao_exe(path):
    try:
        pe = pefile.PE(path)
        if not 'VS_FIXEDFILEINFO' in pe.__dict__:
            return None
        ver = pe.VS_FIXEDFILEINFO[0]
        # Formata para a.b.c.d
        file_ver = f"{ver.FileVersionMS >> 16}.{ver.FileVersionMS & 0xFFFF}.{ver.FileVersionLS >> 16}.{ver.FileVersionLS & 0xFFFF}"
        return file_ver
    except Exception as e:
        print(f"Erro ao ler versão PE: {e}")
        return None

def criar_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def processar_app(app):
    print(f"--- Processando {app['name']} ---")
    
    if not baixar_arquivo(app["url"], TEMP_FILE):
        return

    versao = obter_versao_exe(TEMP_FILE)
    if not versao or versao == "0.0.0.0":
        print(f"ERRO: Não foi possível detectar a versão de {app['name']}")
        if os.path.exists(TEMP_FILE): os.remove(TEMP_FILE)
        return

    print(f"Versão detectada: {versao}")
    
    # Estrutura de pastas oficial: manifests/p/Publisher/App/Versao
    publisher_folder = app['publisher'].replace(" ", "")
    app_folder = app['name'].replace(" ", "")
    caminho_final = f"{BASE_PATH}/{publisher_folder[0].lower()}/{publisher_folder}/{app_folder}/{versao}"
    
    Path(caminho_final).mkdir(parents=True, exist_ok=True)
    
    hash_file = calcular_sha256(TEMP_FILE)

    # 1. Manifesto de Versão
    criar_yaml(f"{caminho_final}/{app['id']}.yaml", {
        "PackageIdentifier": app["id"],
        "PackageVersion": versao,
        "PackageLocale": "en-US",
        "Publisher": app["publisher"],
        "PackageName": app["name"],
        "License": "Proprietary",
        "ShortDescription": f"Auto-generated package for {app['name']}",
        "ManifestType": "version",
        "ManifestVersion": "1.4.0"
    })

    # 2. Manifesto de Locale
    criar_yaml(f"{caminho_final}/{app['id']}.locale.en-US.yaml", {
        "PackageIdentifier": app["id"],
        "PackageVersion": versao,
        "PackageLocale": "en-US",
        "Publisher": app["publisher"],
        "PackageName": app["name"],
        "ShortDescription": f"{app['name']} version {versao}",
        "ManifestType": "defaultLocale",
        "ManifestVersion": "1.4.0"
    })

    # 3. Manifesto de Instalador
    criar_yaml(f"{caminho_final}/{app['id']}.installer.yaml", {
        "PackageIdentifier": app["id"],
        "PackageVersion": versao,
        "InstallerType": "exe", # Assumindo EXE padrão
        "Installers": [
            {
                "Architecture": "x64",
                "InstallerUrl": app["url"],
                "InstallerSha256": hash_file,
                "InstallerSwitches": {
                    "Silent": "/S" if "SilentArgs" not in app else app["SilentArgs"],
                    "SilentWithProgress": "/S" if "SilentArgs" not in app else app["SilentArgs"]
                }
            }
        ],
        "ManifestType": "installer",
        "ManifestVersion": "1.4.0"
    })

    # Limpeza
    if os.path.exists(TEMP_FILE):
        os.remove(TEMP_FILE)
    print("Manifests criados com sucesso.")

def main():
    if not os.path.exists("scripts/apps.json"):
        print("Arquivo scripts/apps.json não encontrado!")
        return

    with open("scripts/apps.json", "r", encoding="utf-8") as f:
        apps = json.load(f)

    for app in apps:
        processar_app(app)

if __name__ == "__main__":
    main()
