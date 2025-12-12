import os
import json
import requests
import hashlib
import yaml
import pefile
from pathlib import Path

BASE_PATH = "manifests"
TEMP_FILE = "temp_installer.exe"

def processar_app(app):
    print(f"--- Processando: {app['name']} ---")
    print(f"Link inicial: {app['url']}")

    # 1. Baixar e Resolver URL Real
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        # allow_redirects=True segue o link até o arquivo final
        r = requests.get(app["url"], stream=True, headers=headers, allow_redirects=True)
        r.raise_for_status()

        # CAPTURA A URL FINAL (Ex: muda de 'go.nvidia.com' para 'download.nvidia.com/...v11.exe')
        final_url = r.url
        print(f"Link final resolvido: {final_url}")

        with open(TEMP_FILE, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    except Exception as e:
        print(f"ERRO FATAL ao baixar: {e}")
        return

    # 2. Detectar Versão
    versao = None
    try:
        pe = pefile.PE(TEMP_FILE)
        if 'VS_FIXEDFILEINFO' in pe.__dict__:
            ver = pe.VS_FIXEDFILEINFO[0]
            versao = f"{ver.FileVersionMS >> 16}.{ver.FileVersionMS & 0xFFFF}.{ver.FileVersionLS >> 16}.{ver.FileVersionLS & 0xFFFF}"
    except Exception:
        pass

    # Fallback para versão manual se falhar
    if not versao or versao == "0.0.0.0":
        if "manualVersion" in app:
            versao = app["manualVersion"]
            print(f"Usando versão manual: {versao}")
        else:
            print("AVISO: Versão não detectada. Usando 'Latest' como placeholder.")
            versao = "0.0.0.1" # Evita quebrar o script

    print(f"Versão definida: {versao}")

    # 3. Criar Pastas e Hash
    publisher = app['publisher'].replace(" ", "")
    name = app['name'].replace(" ", "")
    path_dir = f"{BASE_PATH}/{publisher[0].lower()}/{publisher}/{name}/{versao}"
    Path(path_dir).mkdir(parents=True, exist_ok=True)
    
    hash_file = hashlib.sha256()
    with open(TEMP_FILE, "rb") as f:
        while chunk := f.read(8192):
            hash_file.update(chunk)
    hash_str = hash_file.hexdigest()

    # 4. Gerar YAMLs (Usando final_url)
    # Manifest Principal
    criar_yaml(f"{path_dir}/{app['id']}.yaml", {
        "PackageIdentifier": app["id"],
        "PackageVersion": versao,
        "PackageLocale": "en-US",
        "Publisher": app["publisher"],
        "PackageName": app["name"],
        "ManifestType": "version",
        "ManifestVersion": "1.4.0"
    })

    # Manifest Installer
    criar_yaml(f"{path_dir}/{app['id']}.installer.yaml", {
        "PackageIdentifier": app["id"],
        "PackageVersion": versao,
        "InstallerType": "exe",
        "Installers": [{
            "Architecture": "x64",
            "InstallerUrl": final_url, # <--- AQUI ESTÁ O TRUQUE
            "InstallerSha256": hash_str
        }],
        "ManifestType": "installer",
        "ManifestVersion": "1.4.0"
    })
    
    # Manifest Locale
    criar_yaml(f"{path_dir}/{app['id']}.locale.en-US.yaml", {
        "PackageIdentifier": app["id"],
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

def criar_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def main():
    if not os.path.exists("scripts/apps.json"):
        return
    with open("scripts/apps.json", "r", encoding="utf-8") as f:
        apps = json.load(f)
    for app in apps:
        processar_app(app)

if __name__ == "__main__":
    main()
