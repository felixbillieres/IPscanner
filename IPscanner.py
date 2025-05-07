#!/usr/bin/env python3
import argparse
import subprocess
import os
import time
from datetime import datetime

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'exécution: {e}")
        return None

def create_output_dir(target, base_dir="scans"):
    # Remplace les caractères non alphanumériques de la cible par des underscores pour le nom de dossier
    safe_target_name = "".join(c if c.isalnum() else "_" for c in target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"{base_dir}_{safe_target_name}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def quick_scan(target, output_dir, scan_type="tcp"):
    print(f"\n[⚡] Début du scan {scan_type.upper()} rapide...")
    output_file = f"{output_dir}/initial_scan_{scan_type}.nmap"
    command = f"nmap -v -n -Pn -sS -T4 --max-retries 1 --min-rate 1000 -p- {target} -oN {output_file}"
    if scan_type == "udp":
        command = f"nmap -v -n -Pn -sU -T4 --max-retries 1 --min-rate 500 -p- {target} -oN {output_file}"
    
    run_command(command)
    return parse_open_ports(output_file)

def parse_open_ports(nmap_file):
    ports = []
    with open(nmap_file, 'r') as f:
        for line in f:
            if '/tcp' in line and 'open' in line:
                ports.append(line.split('/')[0])
            elif '/udp' in line and 'open' in line:
                ports.append(line.split('/')[0])
    return ','.join(ports)

def deep_scan(target, ports, output_dir, scan_type="tcp"):
    if not ports:
        return
    
    print(f"\n[🔍] Scan approfondi {scan_type.upper()} sur les ports: {ports}")
    output_file = f"{output_dir}/deep_scan_{scan_type}.nmap"
    command = f"nmap -v -n -Pn -sCV -T4 -p{ports} {target} -oN {output_file}"
    if scan_type == "udp":
        command = f"nmap -v -n -Pn -sU -sCV -T4 -p{ports} {target} -oN {output_file}"
    
    run_command(command)
    return output_file

def parse_versions(nmap_file, output_dir):
    print(f"\n[📄] Extraction des versions logicielles...")
    versions = []
    
    with open(nmap_file, 'r') as f:
        for line in f:
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 4:
                    port_proto = parts[0]
                    service = parts[2]
                    version = ' '.join(parts[4:])
                    versions.append(f"{port_proto} - {service} {version}")
    
    version_file = f"{output_dir}/versions.txt"
    with open(version_file, 'w') as f:
        f.write("=== Versions logicielles détectées ===\n\n")
        f.write('\n'.join(versions))
    
    print(f"[✅] Versions sauvegardées dans: {version_file}")

def main():
    parser = argparse.ArgumentParser(description="Outil de scan réseau personnel")
    parser.add_argument("target", help="Cible à scanner (IP ou domaine)")
    parser.add_argument("-o", "--output", help="Répertoire de sortie de base (ex: mes_scans). Un sous-dossier avec la cible et l'horodatage sera créé.")
    parser.add_argument("--udp", action="store_true", help="Activer le scan UDP")
    args = parser.parse_args()

    # Utilise le répertoire de sortie fourni ou le répertoire par défaut "scans"
    # create_output_dir se chargera d'ajouter le nom de la cible et l'horodatage
    base_output_dir = args.output if args.output else "scans"
    output_dir = create_output_dir(args.target, base_output_dir)
    
    open_ports = {'tcp': '', 'udp': ''}

    # Scan TCP
    open_ports['tcp'] = quick_scan(args.target, output_dir, "tcp")
    deep_scan_file_tcp = deep_scan(args.target, open_ports['tcp'], output_dir, "tcp")
    
    # Scan UDP si activé
    deep_scan_file_udp = None
    if args.udp:
        open_ports['udp'] = quick_scan(args.target, output_dir, "udp")
        deep_scan_file_udp = deep_scan(args.target, open_ports['udp'], output_dir, "udp")

    # Extraction des versions
    # On vérifie si l'un des fichiers de scan approfondi existe avant de parser
    # Priorité au fichier TCP s'il existe, sinon UDP.
    final_deep_scan_file_for_versions = None
    if deep_scan_file_tcp: # Si le scan TCP a produit un fichier
        final_deep_scan_file_for_versions = deep_scan_file_tcp
    elif deep_scan_file_udp: # Sinon, si le scan UDP a produit un fichier (cas où TCP n'a rien trouvé ou n'a pas été fait)
        final_deep_scan_file_for_versions = deep_scan_file_udp
        
    if final_deep_scan_file_for_versions:
        parse_versions(final_deep_scan_file_for_versions, output_dir)
    
    print(f"\n[🎉] Scan terminé! Résultats dans: {output_dir}")

if __name__ == "__main__":
    main()
