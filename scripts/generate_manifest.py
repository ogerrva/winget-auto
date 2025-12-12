import os
import json
import requests
import hashlib
import yaml
from pathlib import Path

BASE_PATH = "manifests"

def baixar(url, destino):
    r = requests.get(url, stream=True)
    with open(destino, "wb") as f:
        for chunk in r.iter_content(1024):
            f.write(chunk)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(4096), b""):
            h.update(b)
    return h.hexdigest()

def criar_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def gerar_manifest(app):

    # obter versão da API
    versao = requests.get(app["versionApi"]).text.strip()

    print(f"Versão detectada: {versao}")

    # definir pastas
    pasta = f"{BASE_PATH}/{app['publisher'][0].upper()}/{app['publisher']}/{app['name']}/{versao}"
    Path(pasta).mkdir(parents=True, exist_ok=True)

    # baixar instalador temporário
    temp = "temp_installer.exe"
    baixar(app["url"], temp)

    # calcular hash
    hash_inst = sha256(temp)

    # arquivo 1: manifest principal
    criar_yaml(f"{pasta}/{app['publisher']}.{app['name']}.yaml", {
        "Id": app["id"],
        "Publisher": app["publisher"],
        "Name": app["name"],
        "Version": versao,
        "License": "Unknown",
        "ShortDescription": f"{app['name']} package auto-generated."
    })

    # arquivo 2: locale
    criar_yaml(f"{pasta}/{app['publisher']}.{app['name']}.locale.en-US.yaml", {
        "PackageIdentifier": app["id"],
        "PackageVersion": versao,
        "PackageLocale": "en-US",
        "Publisher": app["publisher"],
        "PackageName": app["name"],
        "ShortDescription": f"{app['name']} automatically packaged for winget."
    })

    # arquivo 3: installer
    criar_yaml(f"{pasta}/{app['publisher']}.{app['name']}.installer.yaml", {
        "PackageIdentifier": app["id"],
        "PackageVersion": versao,
        "InstallerType": "exe",
        "Installers": [
            {
                "Architecture": "x64",
                "InstallerUrl": app["url"],
                "InstallerSha256": hash_inst,
                "InstallerSwitches": {
                    "Silent": "/silent",
                    "SilentWithProgress": "/silent"
                }
            }
        ]
    })

    os.remove(temp)

def main():
    with open("scripts/apps.json", "r", encoding="utf-8") as f:
        apps = json.load(f)

    for app in apps:
        print(f"Processando: {app['name']}")
        gerar_manifest(app)

if __name__ == "__main__":
    main()
