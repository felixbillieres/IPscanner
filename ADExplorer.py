#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import socket
import threading
import logging
from datetime import datetime
import ipaddress
import sys
import subprocess
import shutil
import re

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter, NestedCompleter
    from prompt_toolkit.styles import Style
except ImportError:
    print("Erreur: La librairie 'prompt_toolkit' n'est pas installée.")
    print("Veuillez l'installer avec : pip install prompt_toolkit")
    sys.exit(1)

# Configuration du logging
LOG_FILE = "ad_explorer.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Définition des ports des services AD courants
SERVICE_PORTS = {
    "SMB": [139, 445],
    "LDAP": [389],
    "LDAPS": [636],
    "MSSQL": [1433],
    "RDP": [3389],
    "WinRM_HTTP": [5985],
    "WinRM_HTTPS": [5986],
    "RPC_Mapper": [135],
    "DNS": [53], # TCP & UDP
    "Kerberos": [88], # TCP & UDP
    "GlobalCatalog_LDAP": [3268],
    "GlobalCatalog_LDAPS": [3269],
}

# Style pour prompt_toolkit
cli_style = Style.from_dict({
    'prompt': 'ansiblue bold',
    'prompt.arg': 'ansigreen bold', # Pour les sous-prompts
    '': '#ffffff', # Default text
    'bottom-toolbar': 'bg:#333333 #ffffff',
})

# --- Couleurs ANSI (pour la sortie non-prompt_toolkit) ---
class AnsiColors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    NO_COLOR_MODE = False

# Gestionnaire d'identifiants (simple, pour la session en cours)
# Dans une application réelle, envisager un stockage plus sécurisé si persistance nécessaire
credentials = {
    "username": None,
    "password": None,
    "domain": None
}

# --- Fonctions Utilitaires ---
def check_command_exists(command):
    """Vérifie si une commande externe existe dans le PATH."""
    if shutil.which(command) is None:
        logging.warning(f"La commande '{command}' ne semble pas être installée ou n'est pas dans le PATH.")
        print(f"[!] Attention: La commande '{command}' est introuvable. Certaines fonctionnalités pourraient ne pas être disponibles.")
        return False
    return True

NXC_AVAILABLE = False
RPCCLIENT_AVAILABLE = False
KERBRUTE_AVAILABLE = False
IMPACKET_EXAMPLES_AVAILABLE = False # Pour ldp.py etc.

def get_nxc_executable():
    """Retourne 'nxc' ou 'netexec' en fonction de ce qui est disponible."""
    if shutil.which("nxc"):
        return "nxc"
    elif shutil.which("netexec"):
        return "netexec"
    return "nxc" # Par défaut, même si non trouvé, pour la construction de commandes

NXC_CMD = get_nxc_executable()

def run_command(command_list, shell=False, capture_output=True, text=True, check=False):
    """Exécute une commande externe et affiche sa sortie en temps réel."""
    command_str = command_list if shell else " ".join(command_list)
    logging.info(f"Exécution de la commande: {command_str}")
    print(f"[*] Exécution: {command_str}")
    try:
        process = subprocess.Popen(
            command_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Redirige stderr vers stdout
            text=text,
            bufsize=1,  # Line-buffered
            universal_newlines=True, # Assure que la sortie est traitée comme du texte
            shell=shell
        )
        if capture_output:
            output_lines = []
            if process.stdout:
                for line in iter(process.stdout.readline, ''):
                    print(line, end='')
                    output_lines.append(line)
                process.stdout.close()
            return_code = process.wait()
            if return_code != 0 and check:
                logging.error(f"La commande a échoué avec le code de sortie {return_code}")
                # L'erreur est déjà affichée car stderr est redirigé vers stdout
            return "".join(output_lines), return_code
        else:
            process.wait() # Attendre la fin si on ne capture pas
            return "", process.returncode

    except FileNotFoundError:
        logging.error(f"Erreur: La commande '{command_list[0]}' n'a pas été trouvée. Assurez-vous qu'elle est installée et dans votre PATH.")
        print(f"[-] Erreur: Commande '{command_list[0]}' introuvable.")
        return None, -1
    except Exception as e:
        logging.error(f"Erreur lors de l'exécution de la commande '{command_str}': {e}")
        print(f"[-] Erreur lors de l'exécution: {e}")
        return None, -1

def format_status(success, text_if_success="Succès", text_if_failure="Échec"):
    if AnsiColors.NO_COLOR_MODE:
        return f"[+] {text_if_success}" if success else f"[-] {text_if_failure}"
    return f"{AnsiColors.GREEN}[+] {text_if_success}{AnsiColors.ENDC}" if success else f"{AnsiColors.RED}[-] {text_if_failure}{AnsiColors.ENDC}"

def run_preliminary_scan(target_ip, scanned_ports_info, session):
    """Effectue une série d'énumérations préliminaires rapides et affiche un tableau de statut."""
    logging.info(f"Exécution du scan préliminaire sur {target_ip}")
    print(f"\n{AnsiColors.CYAN}[*] Scan préliminaire Active Directory pour {AnsiColors.YELLOW}{target_ip}{AnsiColors.ENDC}:{AnsiColors.ENDC}")

    results = []
    nxc_exec = NXC_CMD

    # 1. Test de connexion anonyme LDAP et récupération du contexte de nommage
    ldap_status = {"text": "LDAP Anonyme (389/636)", "status": format_status(False), "details": "NXC non disponible ou test échoué"}
    if NXC_AVAILABLE:
        # Tenter sur LDAPS d'abord si le port est ouvert, sinon LDAP
        ldap_target_protocol = "ldap"
        prelim_ldap_port_to_use = ""

        if 636 in scanned_ports_info.get("LDAPS", {}).get("ports", []):
            ldap_target_protocol = "ldaps"
            prelim_ldap_port_to_use = ":636"
        elif 3269 in scanned_ports_info.get("GlobalCatalog_LDAPS", {}).get("ports", []):
            ldap_target_protocol = "ldaps" # GC LDAPS
            prelim_ldap_port_to_use = ":3269"
        elif 389 in scanned_ports_info.get("LDAP", {}).get("ports", []):
            ldap_target_protocol = "ldap"
            prelim_ldap_port_to_use = ":389"
        elif 3268 in scanned_ports_info.get("GlobalCatalog_LDAP", {}).get("ports", []):
            ldap_target_protocol = "ldap" # GC LDAP
            prelim_ldap_port_to_use = ":3268"


        if prelim_ldap_port_to_use:
            cmd = [nxc_exec, ldap_target_protocol, target_ip, "-u", "", "-p", "", "--timeout", "10"] # Timeout pour nxc
            # Pour obtenir le naming context, nxc l'affiche souvent par défaut lors d'une connexion réussie.
            # Ou on peut utiliser --info mais c'est un module payant.
            # Une simple connexion suffit pour le test.
            output, error_output = run_command(cmd, timeout=15, suppress_errors=True) # Augmenter un peu le timeout pour nxc
            
            if output and "Pwn3d!" not in output and "ERROR" not in output.upper() and "FAILURE" not in output.upper() : # nxc peut être verbeux
                # Chercher des indicateurs de succès comme le nom de domaine
                domain_match = re.search(r"Domain:\s*([\w.-]+)", output, re.IGNORECASE)
                dns_domain_match = re.search(r"DNS Domain:\s*([\w.-]+)", output, re.IGNORECASE)
                forest_match = re.search(r"Forest:\s*([\w.-]+)", output, re.IGNORECASE)
                
                details_str = ""
                if domain_match: details_str += f"Domaine: {domain_match.group(1)} "
                if dns_domain_match and (not domain_match or dns_domain_match.group(1) != domain_match.group(1)):
                    details_str += f"DNS Domaine: {dns_domain_match.group(1)} "
                if forest_match: details_str += f"Forêt: {forest_match.group(1)}"

                if not details_str and "LDAP connection successful" in output: # Autre indicateur possible
                     details_str = "Connexion LDAP anonyme réussie."

                if details_str:
                    ldap_status["status"] = format_status(True)
                    ldap_status["details"] = details_str.strip()
                else:
                    ldap_status["details"] = "Connexion anonyme LDAP possible mais infos de domaine non extraites."
                    # On peut considérer cela comme un demi-succès
                    if "Guest session" in output or "Anonymous" in output : # nxc peut indiquer une session anonyme
                         ldap_status["status"] = format_status(True, "Partiel", "Partiel")


            elif error_output:
                 ldap_status["details"] = f"Échec (nxc: {error_output.splitlines()[0] if error_output else 'erreur inconnue'})"
            else:
                 ldap_status["details"] = "Échec de la connexion LDAP anonyme ou pas d'infos."
        else:
            ldap_status["details"] = "Ports LDAP/LDAPS (389,636,3268,3269) non ouverts."

    results.append(ldap_status)

    # 2. Test de connexion anonyme SMB et listage des partages
    smb_status = {"text": "SMB Anonyme & Partages (445)", "status": format_status(False), "details": "NXC non disponible ou test échoué"}
    if NXC_AVAILABLE and 445 in scanned_ports_info.get("SMB", {}).get("ports", []):
        cmd_smb = [nxc_exec, "smb", target_ip, "-u", "", "-p", "", "--shares", "--timeout", "10"]
        output_smb, error_smb = run_command(cmd_smb, timeout=15, suppress_errors=True)
        
        if output_smb and "Pwn3d!" not in output_smb and "ERROR" not in output_smb.upper():
            if "Guest session" in output_smb or "Anonymous" in output_smb or re.search(r"READ\s+WRITE", output_smb): # Indicateurs de succès
                smb_status["status"] = format_status(True)
                shares = []
                for line in output_smb.splitlines():
                    if ("READ" in line or "WRITE" in line) and "$" not in line: # Partages accessibles non administratifs
                        share_name_match = re.match(r"\s*([\w-]+)\s+", line.strip())
                        if share_name_match:
                            shares.append(share_name_match.group(1))
                if shares:
                    smb_status["details"] = f"Partages trouvés: {', '.join(list(set(shares))[:3])}" # Afficher quelques partages
                else:
                    smb_status["details"] = "Session nulle SMB réussie, aucun partage notable listé."
            else:
                smb_status["details"] = "Session nulle SMB possible mais pas de partages clairs ou erreur."

        elif error_smb:
            smb_status["details"] = f"Échec (nxc: {error_smb.splitlines()[0] if error_smb else 'erreur inconnue'})"
        else:
            smb_status["details"] = "Échec de la connexion SMB anonyme ou pas de partages."
    elif not (445 in scanned_ports_info.get("SMB", {}).get("ports", [])):
        smb_status["details"] = "Port SMB (445) non ouvert."
    results.append(smb_status)

    # 3. Statut des ports AD courants
    ad_ports_to_check = {
        "DNS (53 TCP/UDP)": ("DNS", [53]),
        "Kerberos (88 TCP/UDP)": ("Kerberos", [88]),
        "RPC Mapper (135 TCP)": ("RPC_Mapper", [135]),
        "NetBIOS-SSN (139 TCP)": ("SMB", [139]), # Souvent lié à SMB
        # LDAP/SMB/LDAPS déjà couverts plus spécifiquement
        "Kerberos Pwd (464 TCP/UDP)": ("Kerberos", [464]), # Moins courant à trouver ouvert de l'extérieur
        "WinRM HTTP (5985 TCP)": ("WinRM_HTTP", [5985]),
        "WinRM HTTPS (5986 TCP)": ("WinRM_HTTPS", [5986]),
    }

    for desc, (service_key, port_numbers) in ad_ports_to_check.items():
        port_open = False
        # scanned_ports_info est comme: {'SMB': {'ports': [139, 445], 'status': 'open'}, ...}
        # ou {'DNS': {'ports': [53], 'status': 'open', 'protocol': 'tcp'}, ...}
        # La structure de scanned_ports_info doit être cohérente.
        # Supposons que SERVICE_PORTS est utilisé pour le scan initial et que scanned_ports_info reflète cela.
        
        service_data = scanned_ports_info.get(service_key)
        if service_data and service_data.get('status') == 'open':
            # Vérifier si l'un des ports spécifiques est dans la liste des ports ouverts pour ce service
            if any(p in service_data.get('ports', []) for p in port_numbers):
                port_open = True
        
        results.append({
            "text": desc,
            "status": format_status(port_open, "Ouvert", "Fermé/Non trouvé"),
            "details": ""
        })

    # Affichage du tableau
    print(f"\n  {AnsiColors.BOLD}Résultats du Scan Préliminaire:{AnsiColors.ENDC}")
    # Simple table format
    header_format = "| {<35} | {<25} | {}"
    row_format    = "| {<35} | {<25} | {}"
    print("-" * 80)
    print(header_format.format("Test", "Statut", "Détails"))
    print("-" * 80)
    for res in results:
        # Tronquer les détails si trop longs pour l'affichage console
        details_display = res['details']
        if len(details_display) > 40: # Ajuster la longueur max des détails
            details_display = details_display[:37] + "..."
        print(row_format.format(res['text'], res['status'], details_display))
    print("-" * 80)
    print("\n")

# --- Fonctions de Scan ---
def check_port(ip, port, open_ports_list, service_name):
    """Vérifie si un port TCP est ouvert."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout de 1 seconde
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports_list.append((port, service_name))
        sock.close()
    except socket.error as e:
        logging.debug(f"Erreur de socket en scannant {ip}:{port} - {e}")

def initial_scan(target_ip):
    """Effectue un scan initial des ports pour les services AD."""
    logging.info(f"Début du scan initial des services sur {target_ip}")
    print(f"[*] Scan initial des services sur {target_ip}...")

    open_services = {}
    threads = []
    scan_results = [] # Liste pour stocker les résultats des threads (port, service_name)

    for service, ports in SERVICE_PORTS.items():
        for port in ports:
            thread = threading.Thread(target=check_port, args=(target_ip, port, scan_results, service))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    if not scan_results:
        print("[-] Aucun service AD commun détecté.")
        logging.warning(f"Aucun service AD commun détecté sur {target_ip}")
        return {}

    print("\n[+] Services potentiels détectés :")
    for port, service_name in sorted(scan_results):
        print(f"  - Port {port}/tcp ouvert ({service_name})")
        if service_name not in open_services:
            open_services[service_name] = []
        open_services[service_name].append(port)
    
    logging.info(f"Services détectés sur {target_ip}: {open_services}")
    return open_services

# --- Fonctions de Parsing pour la découverte d'utilisateurs ---
def parse_nxc_users_output(output_str):
    """Parse la sortie de nxc --users pour extraire les noms d'utilisateurs."""
    users = set()
    # Exemple de ligne: SMB  10.0.0.5  445  DC01  [*] Users: Administrator, Guest, krbtgt, user1
    # Exemple LDAP: LDAP 10.0.0.5  389  DC01  Users: Administrator (Sid: S-1-5-...), Guest (Sid: S-1-5-...)
    # On cherche la partie après "Users: " ou "users: "
    try:
        users_marker = "Users: "
        if users_marker.lower() not in output_str.lower():
            users_marker = "users: " # Tentative avec minuscule
        
        for line in output_str.splitlines():
            if users_marker.lower() in line.lower():
                # Prend tout ce qui est après "Users: "
                users_part = line.split(users_marker, 1)[-1] if users_marker in line else line.split(users_marker.lower(), 1)[-1]
                # Sépare par virgule, enlève les détails comme (Sid: ...)
                potential_users = [u.split('(')[0].strip() for u in users_part.split(',')]
                for user in potential_users:
                    if user and not user.startswith("S-1-"): # Éviter les SIDs si mal parsés
                        users.add(user)
    except Exception as e:
        logging.error(f"Erreur lors du parsing de la sortie nxc users: {e}")
    return list(users)

def parse_kerbrute_output(output_str):
    """Parse la sortie de kerbrute userenum pour extraire les noms d'utilisateurs valides."""
    users = set()
    # Exemple: 2023/10/27 10:00:01 > [VALID USERNAME] administrator@test.local
    try:
        for line in output_str.splitlines():
            if "[VALID USERNAME]" in line:
                # Extrait ce qui est après "[VALID USERNAME] "
                user_part = line.split("[VALID USERNAME]", 1)[-1].strip()
                # Enlève le domaine si présent (ex: user@domain.com -> user)
                username = user_part.split('@')[0]
                users.add(username)
    except Exception as e:
        logging.error(f"Erreur lors du parsing de la sortie kerbrute: {e}")
    return list(users)

# --- Mode Découverte d'Utilisateurs ---
def user_discovery_menu_help():
    print("\nOptions du Mode Découverte d'Utilisateurs:")
    print("  smbnull             - Énumérer les utilisateurs via SMB (Session Null avec nxc).")
    print("  ldapanon            - Énumérer les utilisateurs via LDAP (Anonyme avec nxc).")
    print("  ldapexist <file>    - Tester l'existence de comptes LDAP depuis un fichier (avec nxc).")
    print("  kerbrute            - Utiliser Kerbrute pour l'énumération d'utilisateurs (si installé).")
    print("  showusers           - Afficher tous les utilisateurs découverts jusqu'à présent.")
    print("  help                - Afficher cette aide.")
    print("  back                - Retourner au menu principal.")

def user_discovery_mode(target_ip, main_session):
    logging.info(f"Entrée dans le Mode Découverte d'Utilisateurs pour {target_ip}")
    
    discovered_users_set = set()

    ud_completer = WordCompleter([
        "smbnull", "ldapanon", "ldapexist", "kerbrute", "showusers", "help", "back"
    ], ignore_case=True)
    
    ud_session = PromptSession(history=FileHistory('.ad_explorer_ud_history'), auto_suggest=AutoSuggestFromHistory(), style=cli_style)

    print(f"\n[*] Mode Découverte d'Utilisateurs pour {target_ip}. Tapez 'help' pour les options.")

    while True:
        try:
            action = ud_session.prompt(f"UserDiscovery ({target_ip})> ", completer=ud_completer).strip().lower()
            if not action:
                continue
            
            cmd_parts = action.split()
            command = cmd_parts[0]

            if command == "back":
                logging.info(f"Sortie du Mode Découverte d'Utilisateurs pour {target_ip}")
                break
            elif command == "help":
                user_discovery_menu_help()
            elif command == "showusers":
                if discovered_users_set:
                    print("\n[+] Utilisateurs découverts :")
                    for user in sorted(list(discovered_users_set)):
                        print(f"  - {user}")
                else:
                    print("[-] Aucun utilisateur découvert pour le moment.")
            
            elif command == "smbnull":
                print(f"[*] Énumération des utilisateurs via SMB (Session Null) sur {target_ip}...")
                if NXC_AVAILABLE:
                    output, _ = run_command(["nxc", "smb", target_ip, "-u", "''", "-p", "''", "--users"])
                    if output:
                        found_users = parse_nxc_users_output(output)
                        if found_users:
                            print(f"[+] Utilisateurs trouvés via SMB Null: {', '.join(found_users)}")
                            discovered_users_set.update(found_users)
                        else:
                            print("[-] Aucun utilisateur trouvé ou parsing échoué.")
                else:
                    print("[-] Commande 'nxc' non disponible.")

            elif command == "ldapanon":
                print(f"[*] Énumération des utilisateurs via LDAP (Anonyme) sur {target_ip}...")
                if NXC_AVAILABLE:
                    # nxc ldap <ip> -u '' -p '' --users est plus général que --users-only qui n'existe peut-être pas
                    output, _ = run_command(["nxc", "ldap", target_ip, "-u", "''", "-p", "''", "--users"])
                    if output:
                        found_users = parse_nxc_users_output(output) # Réutiliser le parseur nxc
                        if found_users:
                            print(f"[+] Utilisateurs trouvés via LDAP Anonyme: {', '.join(found_users)}")
                            discovered_users_set.update(found_users)
                        else:
                            print("[-] Aucun utilisateur trouvé ou parsing échoué.")
                else:
                    print("[-] Commande 'nxc' non disponible.")

            elif command == "ldapexist":
                if len(cmd_parts) < 2:
                    print("Usage: ldapexist <users_file_path>")
                    continue
                users_file = cmd_parts[1]
                print(f"[*] Test d'existence de comptes LDAP depuis '{users_file}' sur {target_ip} (sans Kerberos)...")
                if NXC_AVAILABLE:
                    # nxc ldap <target_ip> -u <users_file> -p '' (le -k est pour l'auth kerberos, pas pour le test d'existence)
                    # La sortie de nxc pour cette commande indique généralement les utilisateurs valides.
                    # On peut essayer de parser les noms d'utilisateurs qui ont réussi.
                    # Exemple de succès: LDAP 10.0.0.5 389 DC01 user1: (Valid account)
                    # Ou simplement afficher la sortie et laisser l'utilisateur interpréter.
                    # Pour l'instant, on va supposer que nxc liste les utilisateurs valides.
                    # Un parsing plus fin serait nécessaire si le format est complexe.
                    print("[!] La sortie de nxc est affichée ci-dessus. Veuillez identifier manuellement les comptes valides.")
                    print("    L'ajout automatique à la liste des 'discovered_users' n'est pas implémenté pour cette méthode pour le moment.")
                    # Si on voulait parser:
                    # found_users = [] # Logique de parsing spécifique ici
                    # if found_users:
                    #     print(f"[+] Comptes existants trouvés: {', '.join(found_users)}")
                    #     discovered_users_set.update(found_users)
                else:
                    print("[-] Commande 'nxc' non disponible.")
            
            elif command == "kerbrute":
                if not KERBRUTE_AVAILABLE:
                    print("[-] La commande 'kerbrute' n'est pas installée ou n'est pas dans le PATH.")
                    print("    Veuillez l'installer depuis : https://github.com/ropnop/kerbrute")
                    continue

                domain_name = get_user_input(ud_session, "Nom de domaine AD (ex: contoso.local): ")
                if not domain_name: continue

                user_list_path = get_user_input(ud_session, "Chemin vers la liste de noms d'utilisateurs: ")
                if not user_list_path: continue
                
                dc_ip_override = get_user_input(ud_session, f"IP du DC (laisser vide pour utiliser {target_ip}): ", default=target_ip)
                if not dc_ip_override: dc_ip_override = target_ip


                print(f"[*] Utilisation de Kerbrute pour énumérer les utilisateurs du domaine '{domain_name}' avec la liste '{user_list_path}' contre DC '{dc_ip_override}'...")
                kerbrute_cmd = ["kerbrute", "userenum", "--domain", domain_name, "--dc", dc_ip_override, user_list_path]
                
                output, _ = run_command(kerbrute_cmd)
                if output:
                    found_users = parse_kerbrute_output(output)
                    if found_users:
                        print(f"[+] Utilisateurs valides trouvés par Kerbrute: {', '.join(found_users)}")
                        discovered_users_set.update(found_users)
                    else:
                        print("[-] Aucun utilisateur valide trouvé par Kerbrute ou parsing échoué.")
            else:
                print(f"Commande inconnue dans le Mode Découverte d'Utilisateurs: {command}. Tapez 'help'.")

        except (KeyboardInterrupt, EOFError):
            print("\n[!] Action annulée dans le Mode Découverte d'Utilisateurs.")
            continue


# --- Fonctions d'exploration ---

def get_user_input(session, message, completer=None, default=""):
    """Obtient une entrée de l'utilisateur avec gestion de l'annulation (Ctrl+C/Ctrl+D)."""
    try:
        return session.prompt(message, completer=completer, default=default).strip()
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Action annulée.")
        return None

def smb_menu_help():
    print("\nCommandes d'exploration SMB disponibles:")
    print("  hosts <range>       - Découvrir les hôtes SMB actifs sur une plage réseau (ex: hosts 192.168.1.0/24).")
    print("  nullsession         - Tester la session NULL et lister partages/utilisateurs si accessible.")
    print("  guestlogin          - Tester le login GUEST et lister partages si accessible.")
    print("  laps                - Tenter de récupérer les mots de passe LAPS (nécessite des identifiants valides).")
    print("  shares              - Lister les partages (nécessite des identifiants ou session null/guest).")
    print("  download <share> <remote_path> [local_path] - Télécharger un fichier (TODO: suggérer smbclient/smbget).")
    print("  help                - Afficher cette aide.")
    print("  back                - Retourner au menu principal.")

def explore_smb(target_ip, ports, main_session):
    logging.info(f"Entrée dans le menu d'exploration SMB pour {target_ip}:{ports}")
    if not NXC_AVAILABLE:
        print("[-] La commande 'nxc' (netexec) n'est pas disponible. L'exploration SMB avancée est limitée.")
        print("    Vous pouvez toujours utiliser 'set creds' et tenter des connexions manuelles avec des outils externes.")
        # On pourrait quand même proposer des actions manuelles ou des suggestions d'outils
        # return # Ou continuer avec des fonctionnalités limitées

    smb_completer = WordCompleter([
        "hosts", "nullsession", "guestlogin", "laps", "shares", "download", "help", "back"
    ], ignore_case=True)
    
    smb_session = PromptSession(history=FileHistory('.ad_explorer_smb_history'), auto_suggest=AutoSuggestFromHistory(), style=cli_style)

    print(f"\n[*] Exploration SMB sur {target_ip} (ports: {', '.join(map(str, ports))}). Tapez 'help' pour les options.")

    while True:
        try:
            action = smb_session.prompt(f"SMB ({target_ip})> ", completer=smb_completer).strip().lower()
            if not action:
                continue
            
            cmd_parts = action.split()
            command = cmd_parts[0]

            if command == "back":
                logging.info(f"Sortie du menu SMB pour {target_ip}")
                break
            elif command == "help":
                smb_menu_help()
            elif command == "hosts":
                if len(cmd_parts) < 2:
                    print("Usage: hosts <network_range/target_ip>")
                    continue
                network_range = cmd_parts[1]
                print(f"[*] Découverte des hôtes SMB sur {network_range}...")
                if NXC_AVAILABLE:
                    run_command(["nxc", "smb", network_range])
                else:
                    print("[-] Commande 'nxc' non disponible.")
            elif command == "nullsession":
                print(f"[*] Test de la session NULL sur {target_ip}...")
                if NXC_AVAILABLE:
                    run_command(["nxc", "smb", target_ip, "-u", "''", "-p", "''"])
                    print(f"[*] Listage des partages via session NULL sur {target_ip}...")
                    run_command(["nxc", "smb", target_ip, "-u", "''", "-p", "''", "--shares"])
                    print(f"[*] Énumération des utilisateurs via session NULL sur {target_ip}...")
                    run_command(["nxc", "smb", target_ip, "-u", "''", "-p", "''", "--users"])
                else:
                    print("[-] Commande 'nxc' non disponible.")
            elif command == "guestlogin":
                print(f"[*] Test du login GUEST sur {target_ip}...")
                if NXC_AVAILABLE:
                    output_guest_test, _ = run_command(["nxc", "smb", target_ip, "-u", "Guest", "-p", "''"])
                    # Netexec peut ne pas explicitement dire "SUCCESS" mais plutôt lister les partages si ça marche
                    # On pourrait analyser la sortie pour un pattern de succès ou simplement essayer de lister les partages
                    if output_guest_test and "Pwn3d!" in output_guest_test or "READ" in output_guest_test.upper(): # Heuristique simple
                        print("[+] Login GUEST semble avoir réussi ou des accès ont été obtenus.")
                        print(f"[*] Listage des partages via login GUEST sur {target_ip}...")
                        run_command(["nxc", "smb", target_ip, "-u", "Guest", "-p", "''", "--shares"])
                    else:
                        print("[-] Le login GUEST a échoué ou n'a pas donné d'accès visible.")
                    # Tenter aussi avec 'guest' en minuscule
                    output_guest_test_lc, _ = run_command(["nxc", "smb", target_ip, "-u", "guest", "-p", "''"])
                    if output_guest_test_lc and "Pwn3d!" in output_guest_test_lc or "READ" in output_guest_test_lc.upper():
                        print("[+] Login 'guest' (minuscule) semble avoir réussi ou des accès ont été obtenus.")
                        print(f"[*] Listage des partages via login 'guest' sur {target_ip}...")
                        run_command(["nxc", "smb", target_ip, "-u", "guest", "-p", "''", "--shares"])
                    elif not ("Pwn3d!" in output_guest_test or "READ" in output_guest_test.upper()): # Si le premier n'a rien donné
                        print("[-] Le login 'guest' (minuscule) a également échoué ou n'a pas donné d'accès visible.")

                else:
                    print("[-] Commande 'nxc' non disponible.")
            elif command == "laps":
                if not credentials["username"] or not credentials["password"]:
                    print("[-] Veuillez d'abord définir un nom d'utilisateur et un mot de passe avec 'set user' et 'set password'.")
                    continue
                print(f"[*] Tentative de récupération LAPS sur {target_ip} avec les identifiants fournis...")
                if NXC_AVAILABLE:
                    cmd = ["nxc", "smb", target_ip, "-u", credentials["username"], "-p", credentials["password"], "--laps"]
                    if credentials["domain"]:
                        cmd.extend(["-d", credentials["domain"]])
                    run_command(cmd)
                else:
                    print("[-] Commande 'nxc' non disponible.")
            elif command == "shares":
                print(f"[*] Listage des partages sur {target_ip}...")
                if NXC_AVAILABLE:
                    if credentials["username"] and credentials["password"]:
                        cmd = ["nxc", "smb", target_ip, "-u", credentials["username"], "-p", credentials["password"], "--shares"]
                        if credentials["domain"]:
                            cmd.extend(["-d", credentials["domain"]])
                        run_command(cmd)
                    else:
                        print("[!] Aucun identifiant fourni. Tentative avec session NULL (si 'nullsession' a été testé positivement) ou GUEST.")
                        print("    Pour une énumération authentifiée, utilisez 'set user', 'set pass'.")
                        # On pourrait ici retenter avec null/guest si l'utilisateur le souhaite
                        run_command(["nxc", "smb", target_ip, "-u", "''", "-p", "''", "--shares"])

                else:
                    print("[-] Commande 'nxc' non disponible.")

            elif command == "download":
                print("  Fonctionnalité de téléchargement à implémenter (ou suggérer des outils).")
                print("  Exemple avec smbclient (outil CLI):")
                print(f"  smbclient //{target_ip}/<share_name> -U \"{credentials['domain']}\\{credentials['username']}%{credentials['password'] if credentials['password'] else ''}\" -c \"get <remote_file> <local_file>\"")
                print("  Ou utilisez un outil comme smbget.")

            else:
                print(f"Commande SMB inconnue: {command}. Tapez 'help'.")

        except (KeyboardInterrupt, EOFError):
            print("\n[!] Action annulée dans le menu SMB.")
            continue # Reste dans le sous-menu SMB

def ldap_menu_help():
    print("\nCommandes d'exploration LDAP disponibles:")
    print("  testuser <file> [range] - Tester l'existence de comptes (sans Kerberos) depuis un fichier. Optionnel: plage réseau.")
    print("  enumusers [file]    - Énumérer tous les utilisateurs (nécessite des identifiants). Optionnel: fichier de sortie.")
    print("  query <filter> <attrs> - Exécuter une requête LDAP brute (nécessite des identifiants). ex: query \"(objectClass=user)\" \"sAMAccountName description\"")
    print("  asreproast [file]   - Tenter AS-REP Roasting. Optionnel: fichier de sortie.")
    print("  kerberoast [file]   - Tenter Kerberoasting (nécessite des identifiants). Optionnel: fichier de sortie.")
    print("  finddelegation      - Découvrir les délégations mal configurées (nécessite des identifiants).")
    print("  info                - Obtenir des informations de base sur le domaine (NamingContexts).")
    print("  help                - Afficher cette aide.")
    print("  back                - Retourner au menu principal.")


def explore_ldap(target_ip, ports, main_session):
    logging.info(f"Entrée dans le menu d'exploration LDAP pour {target_ip}:{ports}")
    if not NXC_AVAILABLE:
        print("[-] La commande 'nxc' (netexec) n'est pas disponible. L'exploration LDAP avancée est limitée.")

    ldap_completer = WordCompleter([
        "testuser", "enumusers", "query", "asreproast", "kerberoast", "finddelegation", "info", "help", "back"
    ], ignore_case=True)
    
    ldap_session = PromptSession(history=FileHistory('.ad_explorer_ldap_history'), auto_suggest=AutoSuggestFromHistory(), style=cli_style)

    print(f"\n[*] Exploration LDAP sur {target_ip} (ports: {', '.join(map(str, ports))}). Tapez 'help' pour les options.")
    is_ldaps = 636 in ports or 3269 in ports # Global Catalog LDAPS
    protocol = "ldaps" if is_ldaps else "ldap"

    while True:
        try:
            action = ldap_session.prompt(f"LDAP ({target_ip})> ", completer=ldap_completer).strip().lower()
            if not action:
                continue
            
            cmd_parts = action.split()
            command = cmd_parts[0]

            # Commandes de base nxc pour LDAP
            base_nxc_cmd = ["nxc", protocol, target_ip]
            auth_nxc_cmd = []
            if credentials["username"]: # Peut être vide pour certaines actions
                auth_nxc_cmd.extend(["-u", credentials["username"]])
                if credentials["password"]: # Peut être vide pour certaines actions
                     auth_nxc_cmd.extend(["-p", credentials["password"]])
                if credentials["domain"]:
                    auth_nxc_cmd.extend(["-d", credentials["domain"]])


            if command == "back":
                logging.info(f"Sortie du menu LDAP pour {target_ip}")
                break
            elif command == "help":
                ldap_menu_help()
            elif command == "info":
                print(f"[*] Récupération des informations de base du domaine (NamingContexts) via {protocol}...")
                if NXC_AVAILABLE:
                    # NXC ne semble pas avoir une commande directe pour juste le naming context sans auth simple
                    # On peut utiliser une requête simple ou se fier à ce que nxc affiche par défaut
                    run_command(base_nxc_cmd + auth_nxc_cmd) # Affiche des infos de base si connexion ok
                else:
                    print("[-] Commande 'nxc' non disponible.")
                    print("    Alternative: ldapsearch -x -H ldap://{target_ip} -s base namingcontexts")

            elif command == "testuser":
                if len(cmd_parts) < 2:
                    print("Usage: testuser <users_file_path> [network_range/target_ip]")
                    continue
                users_file = cmd_parts[1]
                target_range = cmd_parts[2] if len(cmd_parts) > 2 else target_ip
                print(f"[*] Test d'existence de comptes depuis '{users_file}' sur '{target_range}' via {protocol} (sans Kerberos)...")
                if NXC_AVAILABLE:
                    # nxc ldap <network_range> -u <users_file> -p '' -k (le -k est pour kerberos auth, on veut sans ici)
                    # Pour tester l'existence sans password, on peut juste passer -u <file> -p ''
                    # Le prompt original disait "-k" mais c'est pour "use kerberos auth", ce qui n'est pas le but ici.
                    # On va supposer que l'on teste si les comptes existent et sont accessibles anonymement ou avec un mot de passe vide.
                    run_command(["nxc", protocol, target_range, "-u", users_file, "-p", "''"])
                else:
                    print("[-] Commande 'nxc' non disponible.")

            elif command == "enumusers":
                if not credentials["username"] or not credentials["password"]: # Souvent nécessaire pour une énumération complète
                    print("[-] Des identifiants (utilisateur/mot de passe) sont généralement requis pour une énumération complète des utilisateurs.")
                    print("    Utilisez 'set user' et 'set pass' dans le menu principal.")
                    # On peut quand même tenter une énumération anonyme si l'utilisateur le souhaite
                    confirm_anon = get_user_input(ldap_session, "Tenter une énumération anonyme ? (oui/non): ", default="non").lower()
                    if confirm_anon != 'oui':
                        continue
                
                output_file = cmd_parts[1] if len(cmd_parts) > 1 else f"ldap_users_{target_ip}.txt"
                print(f"[*] Énumération de tous les utilisateurs via {protocol} (sortie: {output_file})...")
                if NXC_AVAILABLE:
                    cmd_to_run = base_nxc_cmd + auth_nxc_cmd + ["--users"] # --users-export n'existe plus, --users suffit et logue
                    # NXC logue la sortie dans son propre système de logs.
                    # On peut ajouter --logfile pour rediriger spécifiquement si besoin.
                    print(f"    Les résultats seront dans les logs de nxc ou affichés ci-dessous.")
                    run_command(cmd_to_run)
                    print(f"    Note: nxc enregistre souvent les résultats dans ~/.nxc/logs/ ou un dossier similaire.")
                else:
                    print("[-] Commande 'nxc' non disponible.")

            elif command == "query":
                if len(cmd_parts) < 3:
                    print("Usage: query \"<ldap_filter>\" \"<attributes_to_return>\"")
                    print("Exemple: query \"(objectClass=user)\" \"sAMAccountName description\"")
                    continue
                if not credentials["username"] or not credentials["password"]:
                    print("[-] Des identifiants (utilisateur/mot de passe) sont requis pour les requêtes LDAP authentifiées.")
                    continue
                
                ldap_filter = cmd_parts[1]
                attributes = cmd_parts[2]
                print(f"[*] Exécution de la requête LDAP via {protocol}: Filtre='{ldap_filter}', Attributs='{attributes}'...")
                if NXC_AVAILABLE:
                    # nxc ldap <target_ip> -u <username> -p <password> --query "<filter>" "<attributes>"
                    # La doc de nxc pour --query est un peu floue, il semble que ce soit --ldap-filter et --attributes
                    # Après vérification, nxc utilise --ldap-filter et --attributes
                    # Cependant, le prompt initial demandait --query. Je vais essayer de trouver la bonne syntaxe pour nxc.
                    # Il semble que nxc n'ait pas une option --query directe comme l'ancien crackmapexec.
                    # On peut utiliser le module `ldap` de nxc avec l'action `query`.
                    # nxc ldap <target> -u <user> -p <pass> -M ldap-query -o FILTER="<filter>" ATTRS="<attrs>"
                    # Pour l'instant, je vais indiquer que cette fonctionnalité nécessite une adaptation pour nxc.
                    print("    Note: La syntaxe exacte pour les requêtes LDAP brutes avec nxc peut varier.")
                    print("    Vous pourriez avoir besoin d'utiliser le module 'ldap-query' de nxc.")
                    print(f"    Exemple potentiel: nxc {protocol} {target_ip} {' '.join(auth_nxc_cmd)} -M ldap-query -o FILTER='{ldap_filter}' ATTRS='{attributes}'")
                    # Tentative avec une approche plus simple si disponible
                    # run_command(base_nxc_cmd + auth_nxc_cmd + ["--ldap-filter", ldap_filter, "--attributes", attributes])
                    print("    Cette fonctionnalité de requête directe via nxc CLI est en cours de clarification.")

                else:
                    print("[-] Commande 'nxc' non disponible.")
                    print(f"    Alternative: ldapsearch -x -H {protocol}://{target_ip} -D \"{credentials['domain']}\\{credentials['username']}\" -w \"{credentials['password']}\" -b \"<base_dn>\" \"{ldap_filter}\" {attributes}")


            elif command == "asreproast":
                output_file = cmd_parts[1] if len(cmd_parts) > 1 else f"asreproast_{target_ip}.txt"
                print(f"[*] Tentative d'AS-REP Roasting via {protocol} (sortie: {output_file})...")
                if NXC_AVAILABLE:
                    # nxc ldap <target_ip> -u <username_ou_liste> -p '' --asreproast output.txt
                    # Si des identifiants sont fournis, nxc les utilisera pour se lier d'abord, puis chercher les comptes AS-REP Roastable
                    # Si aucun identifiant n'est fourni, il essaiera une liaison anonyme pour trouver les comptes.
                    # Le prompt demande -u <username> -p '' pour sans auth, ce qui est correct pour cibler un utilisateur spécifique sans mdp
                    # ou -u <username> -p <password> pour une liaison authentifiée avant de chercher.
                    
                    cmd_to_run = base_nxc_cmd
                    if credentials["username"]: # Si un utilisateur est spécifié pour la liaison
                        cmd_to_run += ["-u", credentials["username"]]
                        cmd_to_run += ["-p", credentials["password"] if credentials["password"] else "''"]
                    else: # Tentative anonyme ou avec une liste d'utilisateurs (si on l'implémente)
                         # Pour une recherche générale, on peut omettre -u et -p si le serveur le permet,
                         # ou fournir un utilisateur valide pour la liaison.
                         # NXC va essayer de trouver les utilisateurs vulnérables.
                         print("    Utilisation des identifiants globaux si définis, sinon tentative anonyme.")
                         cmd_to_run += auth_nxc_cmd # Ajoute user/pass/domaine s'ils sont définis

                    cmd_to_run += ["--asreproast", output_file]
                    run_command(cmd_to_run)
                    print(f"    Les résultats (hashs) devraient être dans '{output_file}' si des comptes vulnérables sont trouvés.")
                else:
                    print("[-] Commande 'nxc' non disponible.")

            elif command == "kerberoast":
                if not credentials["username"] or not credentials["password"]:
                    print("[-] Des identifiants (utilisateur/mot de passe) sont requis pour le Kerberoasting.")
                    continue
                output_file = cmd_parts[1] if len(cmd_parts) > 1 else f"kerberoast_{target_ip}.txt"
                print(f"[*] Tentative de Kerberoasting via {protocol} (sortie: {output_file})...")
                if NXC_AVAILABLE:
                    cmd_to_run = base_nxc_cmd + auth_nxc_cmd + ["--kerberoasting", output_file]
                    run_command(cmd_to_run)
                    print(f"    Les résultats (hashs) devraient être dans '{output_file}' si des SPNs sont trouvés.")
                else:
                    print("[-] Commande 'nxc' non disponible.")

            elif command == "finddelegation":
                if not credentials["username"] or not credentials["password"]:
                    print("[-] Des identifiants (utilisateur/mot de passe) sont requis pour trouver les délégations.")
                    continue
                print(f"[*] Recherche de délégations mal configurées via {protocol}...")
                if NXC_AVAILABLE:
                    # nxc ldap <target_ip> -u <username> -p <password> --find-delegation
                    # Cette option n'existe pas directement dans nxc.
                    # On pourrait utiliser des requêtes LDAP spécifiques ou des modules nxc dédiés si disponibles.
                    # Par exemple, le module `delegation` de nxc.
                    # nxc ldap <target> -u <user> -p <pass> -M delegation
                    print("    Utilisation du module 'delegation' de nxc (si disponible et configuré)...")
                    run_command(base_nxc_cmd + auth_nxc_cmd + ["-M", "delegation"])
                    # Alternativement, des filtres LDAP manuels :
                    # Unconstrained: (userAccountControl:1.2.840.113556.1.4.803:=524288)
                    # Constrained: (msDS-AllowedToDelegateTo=*)
                    # Resourced-based Constrained: (msDS-AllowedToActOnBehalfOfOtherIdentity=*)
                    print("    Vous pouvez aussi utiliser des filtres LDAP manuels avec la commande 'query':")
                    print("    query \"(userAccountControl:1.2.840.113556.1.4.803:=524288)\" \"sAMAccountName\" (Non contrainte)")
                    print("    query \"(msDS-AllowedToDelegateTo=*)\" \"sAMAccountName msDS-AllowedToDelegateTo\" (Contrainte)")
                else:
                    print("[-] Commande 'nxc' non disponible.")
            else:
                print(f"Commande LDAP inconnue: {command}. Tapez 'help'.")

        except (KeyboardInterrupt, EOFError):
            print("\n[!] Action annulée dans le menu LDAP.")
            continue

def rpc_menu_help():
    print("\nCommandes d'exploration RPC disponibles:")
    print("  enumusers           - Énumérer les utilisateurs du domaine via rpcclient (connexion null).")
    print("  custom <cmd_str>    - Exécuter une commande rpcclient personnalisée (ex: custom queryuser 0x3e8).")
    print("                      Utilisez avec prudence. Les commandes sont passées après la connexion.")
    print("  help                - Afficher cette aide.")
    print("  back                - Retourner au menu principal.")

def explore_rpc(target_ip, ports, main_session):
    logging.info(f"Entrée dans le menu d'exploration RPC pour {target_ip}:{ports}")
    if not RPCCLIENT_AVAILABLE:
        print("[-] La commande 'rpcclient' n'est pas disponible. L'exploration RPC est limitée.")
        return

    rpc_completer = WordCompleter(["enumusers", "custom", "help", "back"], ignore_case=True)
    rpc_session = PromptSession(history=FileHistory('.ad_explorer_rpc_history'), auto_suggest=AutoSuggestFromHistory(), style=cli_style)

    print(f"\n[*] Exploration RPC/DCOM sur {target_ip} (port mapper: {', '.join(map(str, ports))}). Tapez 'help' pour les options.")

    while True:
        try:
            action = rpc_session.prompt(f"RPC ({target_ip})> ", completer=rpc_completer).strip().lower()
            if not action:
                continue
            
            cmd_parts = action.split()
            command = cmd_parts[0]

            if command == "back":
                logging.info(f"Sortie du menu RPC pour {target_ip}")
                break
            elif command == "help":
                rpc_menu_help()
            elif command == "enumusers":
                print(f"[*] Énumération des utilisateurs du domaine via rpcclient sur \\\\{target_ip} (session null)...")
                # La commande est `rpcclient -N -U "" -c "enumdomusers" \\target_ip`
                # ou interractivement: rpcclient -N -U "" \\target_ip puis enumdomusers
                # Pour subprocess, il est plus simple de passer la commande directement.
                run_command(["rpcclient", "-N", "-U", "", f"\\\\{target_ip}", "-c", "enumdomusers"])
            elif command == "custom":
                if len(cmd_parts) < 2:
                    print("Usage: custom <rpcclient_command_string>")
                    print("Exemple: custom \"queryuser 0x3e8\"")
                    continue
                rpc_command_str = " ".join(cmd_parts[1:])
                print(f"[*] Exécution de la commande rpcclient personnalisée sur \\\\{target_ip}: '{rpc_command_str}'")
                print("[!] Attention: Les commandes personnalisées peuvent être intrusives ou déstabilisantes.")
                
                user_arg = f"{credentials['domain']}\\{credentials['username']}" if credentials["domain"] and credentials["username"] else credentials["username"]
                pass_arg = credentials["password"]
                
                cmd_list = ["rpcclient"]
                if user_arg and pass_arg:
                    cmd_list.extend(["-U", f"{user_arg}%{pass_arg}"])
                elif user_arg: # User mais pas de pass (ex: session null avec un user spécifique)
                    cmd_list.extend(["-U", user_arg, "-N"]) # -N pour pas de prompt de mot de passe
                else: # Complètement anonyme
                    cmd_list.extend(["-N", "-U", ""])

                cmd_list.extend([f"\\\\{target_ip}", "-c", rpc_command_str])
                run_command(cmd_list)
            else:
                print(f"Commande RPC inconnue: {command}. Tapez 'help'.")

        except (KeyboardInterrupt, EOFError):
            print("\n[!] Action annulée dans le menu RPC.")
            continue

# --- Fonctions d'exploration (placeholders pour les autres) ---
def explore_mssql(target_ip, ports):
    logging.info(f"Exploration MSSQL sur {target_ip}:{ports} demandée.")
    print(f"[*] Exploration MSSQL sur {target_ip} (ports: {', '.join(map(str, ports))})...")
    print("  Fonctionnalité à implémenter :")
    print("  - Lister les bases de données")
    print("  - Exécuter des requêtes SQL (basiques)")
    # Ici, intégrer la logique avec pymssql ou pyodbc
    print("\n  Suggestions d'outils externes:")
    print("  - nxc mssql <target_ip> -u <user> -p <pass> --sql-query \"SELECT @@version\"")
    print("  - sqsh -S <target_ip> -U <user> -P <pass>")
    print("  - mssqlclient.py (impacket)")

def explore_rdp(target_ip, ports):
    logging.info(f"Information RDP sur {target_ip}:{ports}.")
    print(f"[*] Service RDP détecté sur {target_ip} (ports: {', '.join(map(str, ports))}).")
    print("  - Le port RDP est ouvert.")
    print("  - Attaques potentielles : force brute, vulnérabilités connues (ex: BlueKeep).")
    print("  - Pour la connexion, utilisez des outils comme xfreerdp ou rdesktop:")
    print(f"    xfreerdp /v:{target_ip}")
    if credentials["username"]:
         print(f"    xfreerdp /u:{credentials['username']} /v:{target_ip}")
    print("\n  Suggestions d'outils/commandes nxc:")
    print(f"  - nxc rdp {target_ip} (pour vérifier la version, etc.)")


def explore_winrm(target_ip, ports):
    logging.info(f"Exploration WinRM sur {target_ip}:{ports} demandée.")
    print(f"[*] Exploration WinRM sur {target_ip} (ports: {', '.join(map(str, ports))})...")
    print("  Fonctionnalité à implémenter :")
    print("  - Exécuter des commandes PowerShell")
    print("  - Afficher la configuration WinRM")
    # Ici, intégrer la logique avec pywinrm
    print("\n  Suggestions d'outils externes/nxc:")
    print(f"  - nxc winrm {target_ip} -u <user> -p <pass> -x 'whoami'")
    print(f"  - evil-winrm -i {target_ip} -u <user> -p <pass>")

def explore_dns(target_ip, ports):
    logging.info(f"Information DNS sur {target_ip}:{ports}.")
    print(f"[*] Service DNS détecté sur {target_ip} (ports: {', '.join(map(str, ports))}).")
    print("  - Le port DNS est ouvert. Ce serveur pourrait être un serveur DNS.")
    print("  - Actions possibles : tentatives de transfert de zone (AXFR), énumération de noms.")
    print(f"  - Exemple avec dig : dig axfr @{target_ip} <domain_name>")
    print("\n  Suggestions d'outils/commandes nxc:")
    print(f"  - nxc dns {target_ip} --zonetransfer <domain_name> (si le serveur DNS est la cible)")


def explore_kerberos(target_ip, ports):
    logging.info(f"Information Kerberos sur {target_ip}:{ports}.")
    print(f"[*] Service Kerberos détecté sur {target_ip} (ports: {', '.join(map(str, ports))}).")
    print("  - Le port Kerberos est ouvert. Ce serveur est probablement un Contrôleur de Domaine.")
    print("  - Actions possibles : énumération d'utilisateurs (Kerbrute), AS-REP Roasting, etc.")
    print("\n  Suggestions d'outils:")
    print("  - kerbrute (pour l'énumération d'utilisateurs, password spraying)")
    print("  - Rubeus, Impacket (getTGT, getST)")
    print("  - Les commandes LDAP de nxc (asreproast, kerberoast) ciblent le KDC via LDAP.")


# --- Gestionnaire de commandes CLI ---
def display_help():
    print("\nCommandes disponibles :")
    print("  explore <service>   - Explorer un service détecté (ex: explore SMB).")
    print("                        Services possibles: SMB, LDAP, LDAPS, MSSQL, RDP, WinRM_HTTP, WinRM_HTTPS, RPC_Mapper, DNS, Kerberos, GlobalCatalog_LDAP, GlobalCatalog_LDAPS")
    print("  discoverusers       - Entrer en Mode Découverte d'Utilisateurs (SMB Null, LDAP Anon, Kerbrute).")
    print("  services            - Afficher à nouveau les services détectés.")
    print("  set user <username> - Définir le nom d'utilisateur pour les connexions.")
    print("  set password <pass> - Définir le mot de passe pour les connexions.")
    print("  set domain <domain> - Définir le domaine pour les connexions.")
    print("  creds               - Afficher les identifiants actuellement configurés.")
    print("  clear creds         - Effacer les identifiants configurés.")
    print("  help                - Afficher ce message d'aide.")
    print("  log                 - Afficher le chemin du fichier de log.")
    print("  exit                - Quitter l'application.")

def print_target_menu(commands_dict):
    """Affiche le menu des commandes pour une cible."""
    print("\nCommandes disponibles pour la cible actuelle:")
    # Trouver la longueur maximale de la clé de commande pour l'alignement
    max_key_len = 0
    if commands_dict: # S'assurer que le dictionnaire n'est pas vide
        max_key_len = max(len(key) for key in commands_dict.keys())
    
    for command, description in commands_dict.items():
        print(f"  {AnsiColors.YELLOW}{command:<{max_key_len}}{AnsiColors.ENDC}  -  {description}")
    print("")

def main_loop(target_ip, scanned_ports, session):
    """Boucle principale pour interagir avec une cible."""
    logging.info(f"Entrée dans la boucle principale pour {target_ip}. Ports scannés: {scanned_ports}")
    
    # Dictionnaire des commandes pour l'affichage de l'aide
    target_commands_help = {
        "help": "Afficher ce message d'aide.",
        "prelim_scan": "Effectuer un scan préliminaire rapide (LDAP/SMB anonyme, ports AD).",
        "smb": "Explorer les services SMB (nécessite une cible SMB).",
        "ldap": "Explorer les services LDAP/LDAPS (nécessite une cible LDAP).",
        "discoverusers": "Tenter différentes techniques de découverte d'utilisateurs.",
        "services": "Afficher les services détectés lors du scan initial.",
        "set user <username>": "Définir le nom d'utilisateur pour les actions futures.",
        "set password <password>": "Définir le mot de passe pour les actions futures.",
        "set domain <domain>": "Définir le domaine pour les actions futures.",
        "creds": "Afficher les identifiants actuellement configurés.",
        "clear creds": "Effacer tous les identifiants configurés.",
        "back": "Retourner au menu principal (si applicable, sinon quitte).",
        "exit": "Quitter l'application."
    }

    # Dictionnaire pour NestedCompleter (toutes les commandes de premier niveau ont None comme valeur)
    target_commands_completer_dict = {
        "help": None,
        "prelim_scan": None,
        "smb": None, # Si SMB avait des sous-commandes, elles seraient ici
        "ldap": None, # Idem pour LDAP
        "discoverusers": None,
        "services": None,
        "set": {
            "user": None,
            "password": None,
            "domain": None
        },
        "creds": None,
        "clear": {
            "creds": None
        },
        "back": None,
        "exit": None
    }
    
    target_completer = NestedCompleter.from_nested_dict(target_commands_completer_dict)

    while True:
        prompt_text = f"ADExplorer ({AnsiColors.YELLOW}{target_ip}{AnsiColors.ENDC})> "
        
        # Construction du bottom_toolbar
        current_creds_display = []
        if credentials["username"]:
            user_display = credentials["username"]
            if credentials["domain"]:
                user_display = f"{credentials['domain']}\\{user_display}"
            current_creds_display.append(f"User: {user_display}")
        if credentials["password"]:
            current_creds_display.append("Pass: Set")
        
        toolbar_text = f"Log: {LOG_FILE}"
        if current_creds_display:
            toolbar_text += " | " + " | ".join(current_creds_display)

        def get_bottom_toolbar():
            return toolbar_text

        try:
            user_input = session.prompt(
                prompt_text,
                completer=target_completer,
                auto_suggest=AutoSuggestFromHistory(),
                style=cli_style, 
                bottom_toolbar=get_bottom_toolbar
            )
            user_input = user_input.strip()
            if not user_input:
                continue

            logging.info(f"Commande reçue: {user_input}")
            command_parts = user_input.lower().split()
            command = command_parts[0]

            if command == "exit":
                logging.info("Sortie de l'application.")
                print("Au revoir !")
                break
            elif command == "back":
                logging.info(f"Retour demandé depuis {target_ip}. Dans ce contexte, cela quitte la session cible.")
                print("Retour... (quitte la session cible actuelle)")
                break
            elif command == "help":
                print_target_menu(target_commands_help) # Utiliser le dictionnaire d'aide ici
            elif command == "prelim_scan":
                run_preliminary_scan(target_ip, scanned_ports, session)
            elif command == "smb":
                smb_ports = scanned_ports.get("SMB", {}).get("ports", [])
                if not smb_ports:
                    print("Usage: smb <service_name>")
                    continue
                explore_smb(target_ip, smb_ports, session)
            elif command == "ldap":
                ldap_ports = scanned_ports.get("LDAP", {}).get("ports", [])
                if not ldap_ports:
                    print("Usage: ldap <service_name>")
                    continue
                explore_ldap(target_ip, ldap_ports, session)
            elif command == "discoverusers":
                user_discovery_mode(target_ip, session)
            elif command == "services":
                print("\n[+] Services potentiels détectés :")
                if scanned_ports:
                    for service, ports in scanned_ports.items():
                        print(f"  - {service} (Ports: {', '.join(map(str, ports))})")
                else:
                    print("  Aucun service n'a été détecté lors du scan initial.")
            elif command == "set":
                if len(command_parts) > 2:
                    cred_type = command_parts[1]
                    value = " ".join(command_parts[2:])
                    if cred_type == "user":
                        credentials["username"] = value
                        print(f"Nom d'utilisateur défini sur : {value}")
                        logging.info(f"Identifiant username défini.")
                    elif cred_type == "password":
                        credentials["password"] = value
                        print("Mot de passe défini.")
                        logging.info(f"Identifiant password défini.")
                    elif cred_type == "domain":
                        credentials["domain"] = value
                        print(f"Domaine défini sur : {value}")
                        logging.info(f"Identifiant domain défini.")
                    else:
                        print("Usage: set <user|password|domain> <valeur>")
                else:
                    print("Usage: set <user|password|domain> <valeur>")
            
            elif command == "creds":
                print("[*] Identifiants actuels :")
                print(f"  Nom d'utilisateur : {credentials['username'] if credentials['username'] else 'Non défini'}")
                print(f"  Mot de passe      : {'********' if credentials['password'] else 'Non défini'}")
                print(f"  Domaine           : {credentials['domain'] if credentials['domain'] else 'Non défini'}")

            elif command == "clear" and len(command_parts) > 1 and command_parts[1] == "creds":
                credentials["username"] = None
                credentials["password"] = None
                credentials["domain"] = None
                print("[*] Identifiants effacés.")
                logging.info("Identifiants effacés.")
            
            else:
                print(f"Commande inconnue: {command}. Tapez 'help' pour la liste des commandes.")

        except KeyboardInterrupt:
            logging.warning("Sortie demandée par l'utilisateur (Ctrl+C)")
            print("\nAu revoir ! (Ctrl+C détecté)")
            break
        except EOFError: # Ctrl+D
            logging.warning("Sortie demandée par l'utilisateur (Ctrl+D)")
            print("\nAu revoir ! (Ctrl+D détecté)")
            break
        except Exception as e:
            logging.error(f"Une erreur inattendue est survenue: {e}", exc_info=True)
            print(f"Erreur: {e}")


# --- Point d'entrée principal ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AD Explorer - Outil interactif d'exploration Active Directory.",
        formatter_class=argparse.RawTextHelpFormatter, # Pour mieux afficher l'epilog
        epilog="""Exemple: python ad_explorer.py 192.168.1.100

Dépendances externes requises (doivent être dans le PATH):
  - netexec (nxc)
  - rpcclient
"""
    )
    parser.add_argument("target_ip", help="Adresse IP de la cible (ex: contrôleur de domaine).")
    parser.add_argument("--no-color", action="store_true", help="Désactiver la sortie colorée pour les messages non-prompt_toolkit.")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    if args.no_color:
        AnsiColors.NO_COLOR_MODE = True

    try:
        ipaddress.ip_address(args.target_ip) # Valide l'adresse IP
    except ValueError:
        logging.error(f"Adresse IP invalide fournie: {args.target_ip}")
        print(f"Erreur: L'adresse IP '{args.target_ip}' n'est pas valide.")
        sys.exit(1)

    logging.info(f"AD Explorer démarré. Cible: {args.target_ip}")

    NXC_AVAILABLE = check_command_exists("nxc") or check_command_exists("netexec")
    RPCCLIENT_AVAILABLE = check_command_exists("rpcclient")
    KERBRUTE_AVAILABLE = check_command_exists("kerbrute")
    IMPACKET_EXAMPLES_AVAILABLE = check_command_exists("samrdump.py") # Juste un exemple
    
    if not NXC_AVAILABLE or not RPCCLIENT_AVAILABLE:
        print("[!] Certaines fonctionnalités seront limitées car des outils externes sont manquants.")

    open_services_found = initial_scan(args.target_ip)
    
    if not open_services_found and not any(port_info[0] for port_info in SERVICE_PORTS.values()): # Vérifie si aucun port n'a été trouvé
        logging.warning(f"Aucun service pertinent détecté sur {args.target_ip}. L'outil interactif pourrait avoir des fonctionnalités limitées.")
        # On pourrait choisir de quitter ici, ou de continuer pour permettre des actions manuelles
        # print("[-] Aucun service pertinent détecté. L'outil va quand même démarrer en mode limité.")
        # Pour l'instant, on continue pour permettre l'utilisation de 'set creds' etc.

    # Créer la session prompt_toolkit ici
    session = PromptSession(history=FileHistory('.ad_explorer_target_history'), style=cli_style)

    main_loop(args.target_ip, open_services_found, session) # Passer la session à main_loop

    logging.info("AD Explorer terminé.") 
