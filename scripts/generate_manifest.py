import os
import json
import requests
import hashlib
import yaml
import pefile  # Nova biblioteca para ler versões
from pathlib import Path

BASE_PATH = "manifests"

def baixar(url, destino):
    print(f"Baixando: {url}")
    headers = {'User-Agent': 'Mozilla/5.0'}
    r = requests.get(url, stream=True, headers=headers)
    if r.status_code != 200:
        raise Exception(f"Erro ao baixar: {r.status_code}")
    with open(destino, "wb") as f:
        for chunk in r.iter_content(1024):
            f.write(chunk)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(4096), b""):
            h.update(b)
    return h.hexdigest()

def obter_versao_exe(path):
    try:
        pe = pefile.PE(path)
        if not 'VS_FIXEDFILEINFO' in pe.__dict__:
            return None
        ver = pe.VS_FIXEDFILEINFO[0]
        # Formato: 11.0.5.420
        file_ver = f"{ver.FileVersionMS >> 16}.{ver.FileVersionMS & 0xFFFF}.{ver.FileVersionLS >> 16}.{ver.FileVersionLS & 0xFFFF}"
        return file_ver
    except Exception as e:
        print(f"Erro ao ler versão PE: {e}")
        return None

def criar_yaml(path, data):
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

def gerar_manifest(app):
    temp = "temp_installer.exe"
    
    try:
        baixar(app["url"], temp)
        
        # Agora a versão vem do arquivo, não da internet
        versao = obter_versao_exe(temp)
        
        if not versao or versao == "0.0.0.0":
            # Fallback: Se não conseguir ler, usa uma data ou erro
            print(f"ALERTA: Não foi possível ler a versão de {app['name']}. Verifique o arquivo.")
            return

        print(f"Versão detectada no EXE: {versao}")

        pasta = f"{BASE_PATH}/{app['publisher'][0].upper()}/{app['publisher']}/{app['name']}/{versao}"
        Path(pasta).mkdir(parents=True, exist_ok=True)

        hash_inst = sha256(temp)

        # Manifest Principal
        criar_yaml(f"{pasta}/{app['publisher']}.{app['name']}.yaml", {
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

        # Manifest Locale
        criar_yaml(f"{pasta}/{app['publisher']}.{app['name']}.locale.en-US.yaml", {
            "PackageIdentifier": app["id"],
            "PackageVersion": versao,
            "PackageLocale": "en-US",
            "Publisher": app["publisher"],
            "PackageName": app["name"],
            "ShortDescription": f"{app['name']} detected version {versao}",
            "ManifestType": "defaultLocale",
            "ManifestVersion": "1.4.0"
        })

        # Manifest Installer
        criar_yaml(f"{pasta}/{app['publisher']}.{app['name']}.installer.yaml", {
            "PackageIdentifier": app["id"],
            "PackageVersion": versao,
            "InstallerType": "exe", # Assume EXE por enquanto
            "Installers": [
                {
                    "Architecture": "x64",
                    "InstallerUrl": app["url"],
                    "InstallerSha256": hash_inst,
                    "InstallerSwitches": {
                        "Silent": "/S" if "SilentArgs" not in app else app["SilentArgs"],
                        "SilentWithProgress": "/S" if "SilentArgs" not in app else app["SilentArgs"]
                    }
                }
            ],
            "ManifestType": "installer",
            "ManifestVersion": "1.4.0"
        })

    except Exception as e:
        print(f"Falha ao processar {app['name']}: {e}")
    finally:
        if os.path.exists(temp):
            os.remove(temp)

def main():
    with open("scripts/apps.json", "r", encoding="utf-8") as f:
        apps = json.load(f)

    for app in apps:
        print(f"Processando: {app['name']}")
        gerar_manifest(app)

if __name__ == "__main__":
    main()
