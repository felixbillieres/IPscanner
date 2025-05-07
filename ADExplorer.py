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
import os

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

# Nouvelle structure pour les tests d'identifiants multiples
multi_credentials = {
    "users": [],
    "passwords": [],
    "hashes": [],
    "users_file": None,
    "passwords_file": None,
    "hashes_file": None,
    "domain": None # Le domaine est partagé
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
    print(f"\n[*] Scan préliminaire Active Directory pour {target_ip}:")

    results = []

    # 1. Test de connexion LDAP anonyme
    ldap_anon_success = False
    ldap_domain_name = "N/A"
    # Vérifier si le port LDAP est ouvert avant de tester
    if 389 in scanned_ports_info.get("LDAP", []): # Accès corrigé
        print("[*] Test de la liaison LDAP anonyme...")
        # Remplacement de --trusted-domain par --namingcontexts ou une simple vérification
        # cmd_ldap_anon = [NXC_CMD, "ldap", target_ip, "-u", "''", "-p", "''", "--trusted-domain"]
        cmd_ldap_anon = [NXC_CMD, "ldap", target_ip, "-u", "", "-p", "", "--info"] # --info est plus général
        output, ret_code = run_command(cmd_ldap_anon)

        # Une meilleure vérification du succès pour la liaison anonyme
        # Souvent, si la commande ne retourne pas d'erreur explicite de login et affiche des infos, c'est un succès.
        # Pour nxc, une absence d'erreur et la présence d'informations de base est un bon signe.
        if ret_code == 0 and output: # Si la commande s'exécute sans erreur et retourne quelque chose
            ldap_anon_success = True
            # Essayer d'extraire le nom de domaine (simpliste)
            match_dns_domain = re.search(r"Domain:\s*([\w.-]+)", output, re.IGNORECASE)
            if match_dns_domain:
                ldap_domain_name = match_dns_domain.group(1)
            else:
                # Tenter d'extraire de defaultNamingContext ou dNSHostName
                match_naming_context = re.search(r"defaultNamingContext:\s*(DC=[\w,-]+)", output, re.IGNORECASE)
                if match_naming_context:
                    ldap_domain_name = match_naming_context.group(1).replace("DC=", "").replace(",", ".")
                else:
                    match_host = re.search(r"dNSHostName:\s*([\w.-]+)", output, re.IGNORECASE)
                    if match_host:
                        # Ceci est le FQDN de la machine, pas nécessairement le domaine AD, mais mieux que rien
                        ldap_domain_name = ".".join(match_host.group(1).split('.')[1:]) if '.' in match_host.group(1) else match_host.group(1)
            if ldap_domain_name == "N/A" and "namingContexts" in output: # Fallback si on a des naming contexts
                ldap_domain_name = "Infos NamingContext trouvées"

    results.append(("LDAP Anonyme", ldap_anon_success, f"Domaine/Infos: {ldap_domain_name}" if ldap_anon_success else "Échec de la liaison ou infos non trouvées"))

    # 2. Test de connexion SMB anonyme (Null Session) & Listage des partages
    smb_anon_success = False
    smb_shares_count = 0
    if 445 in scanned_ports_info.get("SMB", []): # Accès corrigé
        print("[*] Test de la session SMB nulle et listage des partages...")
        cmd_smb_null = [NXC_CMD, "smb", target_ip, "-u", "", "-p", "", "--shares"]
        output, ret_code = run_command(cmd_smb_null)
        if output and "READ" in output.upper() or "WRITE" in output.upper(): # Un indicateur que des partages ont été listés
            smb_anon_success = True # Considérer comme un succès si la commande s'exécute et liste quelque chose
            smb_shares_count = len(re.findall(r"^\s*([\w\-$]+)\s+", output, re.MULTILINE)) # Compte approximatif

    results.append(("SMB Anonyme (Shares)", smb_anon_success, f"{smb_shares_count} partages listés" if smb_anon_success and smb_shares_count > 0 else ("Session nulle possible mais pas de partages listés" if smb_anon_success else "Échec session nulle")))
    
    # 3. Vérification des ports AD courants (basé sur scanned_ports_info)
    # scanned_ports_info est déjà le dictionnaire { "SERVICE": [ports] }
    ad_ports_to_check = {
        "LDAP (389)": ("LDAP", 389),
        "LDAPS (636)": ("LDAPS", 636),
        "SMB (445)": ("SMB", 445), # 139 est aussi SMB mais 445 est plus courant pour AD moderne
        "Kerberos (88)": ("Kerberos", 88),
        "DNS (53)": ("DNS", 53),
        "GlobalCatalog LDAP (3268)": ("GlobalCatalog_LDAP", 3268),
        "GlobalCatalog LDAPS (3269)": ("GlobalCatalog_LDAPS", 3269),
        "RPC Mapper (135)": ("RPC_Mapper", 135),
    }

    for display_name, (service_key, port_num) in ad_ports_to_check.items():
        is_open = port_num in scanned_ports_info.get(service_key, []) # Accès corrigé
        results.append((display_name, is_open, "Ouvert" if is_open else "Fermé/Non détecté"))

    # Affichage du tableau
    print("\n--- Tableau de Statut Préliminaire ---")
    max_test_len = max(len(r[0]) for r in results) if results else 20
    print(f"{'Test':<{max_test_len}} | {'Statut':<8} | {'Détails'}")
    print(f"{'-'*(max_test_len)} | {'-'*8} | {'-'*20}")
    for test_name, status, detail in results:
        status_str = format_status(status, "OK", "FAIL")
        print(f"{test_name:<{max_test_len}} | {status_str:<18} | {detail}") # Ajuster la largeur de status_str si besoin
    print("--- Fin du Tableau ---")

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


def explore_ldap(target_ip, ldap_ports, session):
    """Menu interactif pour explorer les services LDAP/LDAPS."""
    ldap_menu_prompt = f"ADExplorer ({AnsiColors.YELLOW}{target_ip}{AnsiColors.ENDC}/LDAP)> "
    
    ldap_commands_help = {
        "help": "Afficher ce message d'aide.",
        "query <filter> [attributes]": "Effectuer une requête LDAP (ex: query \"(objectClass=user)\" sAMAccountName displayName).",
        "asreproast <output_file.txt>": "Tenter une attaque AS-REP Roasting.",
        "back": "Retourner au menu précédent."
    }
    # Pour NestedCompleter, les commandes finales ont None comme valeur
    ldap_commands_completer = {
        "help": None,
        "query": None, # L'utilisateur tapera le filtre ensuite
        "asreproast": None, # L'utilisateur tapera le nom du fichier
        "back": None,
    }
    ldap_completer = NestedCompleter.from_nested_dict(ldap_commands_completer)

    print_target_menu(ldap_commands_help)

    while True:
        try:
            ldap_input = session.prompt(
                ldap_menu_prompt,
                completer=ldap_completer,
                auto_suggest=AutoSuggestFromHistory(),
                style=cli_style
            ).strip()

            if not ldap_input:
                continue

            parts = ldap_input.split()
            command = parts[0].lower()
            args = parts[1:]

            if command == "back":
                break
            elif command == "help":
                print_target_menu(ldap_commands_help)
            elif command == "query":
                if len(args) < 2:
                    print("Usage: query <ldap_filter> <attributes>")
                    continue
                ldap_filter = args[0]
                attributes = args[1]
                print(f"[*] Exécution de la requête LDAP via ldap: Filtre='{ldap_filter}', Attributs='{attributes}'...")
                if NXC_AVAILABLE:
                    run_command(["nxc", "ldap", target_ip, "-u", "", "-p", "", "--ldap-filter", ldap_filter, "--attributes", attributes])
                else:
                    print(f"    Alternative: ldapsearch -x -H ldap://{target_ip} -D \"{credentials['domain']}\\{credentials['username']}\" -w \"{credentials['password']}\" -b \"<base_dn>\" \"{ldap_filter}\" {attributes}")
            elif command == "asreproast":
                if not args:
                    print("Usage: asreproast <output_file.txt>")
                    continue
                output_file = args[0]
                # Déterminer si SSL doit être utilisé en fonction des ports
                use_ssl = 636 in ldap_ports or 3269 in ldap_ports
                
                # Le domaine est nécessaire pour AS-REP Roasting.
                # Utiliser le domaine globalement défini dans multi_credentials ou credentials
                # Ou demander à l'utilisateur s'il n'est pas défini.
                domain_to_use = multi_credentials.get("domain") or credentials.get("domain")
                if not domain_to_use:
                    try:
                        domain_to_use = session.prompt(
                            "Veuillez entrer le nom de domaine cible pour AS-REP Roasting (ex: contoso.local): ",
                            style=cli_style
                        ).strip()
                        if not domain_to_use:
                            print("[-] Nom de domaine requis pour AS-REP Roasting.")
                            continue
                    except (KeyboardInterrupt, EOFError):
                        print("\nOpération annulée.")
                        continue
                
                print(f"[*] Tentative d'AS-REP Roasting sur {target_ip} pour le domaine {domain_to_use}. Sortie vers {output_file}")
                # nxc ldap <target> [-d <domain>] --asreproast <file> [--ssl si port 636/3269]
                # nxc ne prend pas -u/-p pour asreproast car il cible les comptes sans pré-auth Kerberos
                cmd_asrep = [NXC_CMD, "ldap", target_ip, "-d", domain_to_use, "--asreproast", output_file]
                if use_ssl:
                    cmd_asrep.append("--ssl")
                
                run_command(cmd_asrep, capture_output=False) # Afficher la sortie en direct

            else:
                print(f"Commande LDAP inconnue: {command}")

        except KeyboardInterrupt:
            print("\nRetour au menu précédent (Ctrl+C)")
            break
        except EOFError:
            print("\nRetour au menu précédent (Ctrl+D)")
            break
        except Exception as e:
            logging.error(f"Erreur dans le menu LDAP: {e}", exc_info=True)
            print(f"Erreur: {e}")

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
        "prelim_scan": "Effectuer un scan préliminaire rapide.",
        "smb": "Explorer les services SMB.",
        "ldap": "Explorer les services LDAP/LDAPS.",
        "discoverusers": "Tenter différentes techniques de découverte d'utilisateurs.",
        "services": "Afficher les services détectés.",
        "set user <username>": "Définir l'utilisateur unique pour certaines actions.",
        "set password <password>": "Définir le mot de passe unique.",
        "set domain <domain_name>": "Définir le domaine (pour identifiants uniques ET multiples).",
        "creds": "Afficher les identifiants configurés (uniques et multiples).",
        "clear creds": "Effacer tous les identifiants configurés.",
        "back": "Quitter la session cible actuelle.",
        "exit": "Quitter l'application."
    }

    # Dictionnaire pour NestedCompleter (toutes les commandes de premier niveau ont None comme valeur)
    target_commands_completer_dict = {
        "help": None,
        "prelim_scan": None,
        "smb": None,
        "ldap": None,
        "discoverusers": None,
        "services": None,
        "set": {
            "user": None,
            "password": None,
            "domain": None,
            "users": None,
            "usersfile": None,
            "passwords": None,
            "passwordsfile": None,
            "hashes": None,
            "hashesfile": None,
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
                print_target_menu(target_commands_help)
            elif command == "prelim_scan":
                run_preliminary_scan(target_ip, scanned_ports, session)
            elif command == "smb":
                smb_ports_list = scanned_ports.get("SMB", [])
                if not smb_ports_list:
                    print(f"[-] Aucun port SMB (139, 445) n'a été détecté sur {target_ip}.")
                    logging.warning(f"Tentative d'exploration SMB sans ports SMB détectés pour {target_ip}")
                    continue
                explore_smb(target_ip, smb_ports_list, session)
            elif command == "ldap":
                ldap_ports_list = scanned_ports.get("LDAP", [])
                ldaps_ports_list = scanned_ports.get("LDAPS", [])
                
                combined_ldap_ports = ldap_ports_list + ldaps_ports_list
                
                if not combined_ldap_ports:
                    print(f"[-] Aucun port LDAP (389) ou LDAPS (636) n'a été détecté sur {target_ip}.")
                    logging.warning(f"Tentative d'exploration LDAP sans ports LDAP/LDAPS détectés pour {target_ip}")
                    continue
                explore_ldap(target_ip, combined_ldap_ports, session)
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
                    set_type = command_parts[1].lower()
                    value_parts = command_parts[2:]
                    value = " ".join(value_parts)

                    if set_type == "user":
                        credentials["username"] = value
                        print(f"Utilisateur unique défini sur : {value}")
                        logging.info(f"Identifiant unique 'username' défini.")
                    elif set_type == "password":
                        credentials["password"] = value
                        print("Mot de passe unique défini.")
                        logging.info(f"Identifiant unique 'password' défini.")
                    elif set_type == "domain":
                        credentials["domain"] = value
                        multi_credentials["domain"] = value
                        print(f"Domaine défini sur : {value}")
                        logging.info(f"Domaine '{value}' défini.")
                    elif set_type == "users":
                        multi_credentials["users"] = [u.strip() for u in value.split(',')]
                        multi_credentials["users_file"] = None
                        print(f"Liste d'utilisateurs définie ({len(multi_credentials['users'])} utilisateurs).")
                        logging.info("Liste d'utilisateurs pour multi_credentials définie.")
                    elif set_type == "usersfile":
                        if os.path.isfile(value):
                            multi_credentials["users_file"] = value
                            multi_credentials["users"] = []
                            print(f"Fichier d'utilisateurs défini sur : {value}")
                            logging.info(f"Fichier d'utilisateurs '{value}' pour multi_credentials défini.")
                        else:
                            print(f"[-] Erreur: Fichier '{value}' introuvable.")
                    elif set_type == "passwords":
                        multi_credentials["passwords"] = [p.strip() for p in value.split(',')]
                        multi_credentials["passwords_file"] = None
                        print(f"Liste de mots de passe définie ({len(multi_credentials['passwords'])} mots de passe).")
                        logging.info("Liste de mots de passe pour multi_credentials définie.")
                    elif set_type == "passwordsfile":
                        if os.path.isfile(value):
                            multi_credentials["passwords_file"] = value
                            multi_credentials["passwords"] = []
                            print(f"Fichier de mots de passe défini sur : {value}")
                            logging.info(f"Fichier de mots de passe '{value}' pour multi_credentials défini.")
                        else:
                            print(f"[-] Erreur: Fichier '{value}' introuvable.")
                    elif set_type == "hashes":
                        multi_credentials["hashes"] = [h.strip() for h in value.split(',')]
                        multi_credentials["hashes_file"] = None
                        print(f"Liste de hashes définie ({len(multi_credentials['hashes'])} hashes).")
                        logging.info("Liste de hashes pour multi_credentials définie.")
                    elif set_type == "hashesfile":
                        if os.path.isfile(value):
                            multi_credentials["hashes_file"] = value
                            multi_credentials["hashes"] = []
                            print(f"Fichier de hashes défini sur : {value}")
                            logging.info(f"Fichier de hashes '{value}' pour multi_credentials défini.")
                        else:
                            print(f"[-] Erreur: Fichier '{value}' introuvable.")
                    else:
                        print("Usage: set <user|password|domain|users|usersfile|passwords|passwordsfile|hashes|hashesfile> <valeur>")
                else:
                    print("Usage: set <type> <valeur>")
            
            elif command == "creds":
                print("[*] Identifiants uniques configurés :")
                print(f"  Utilisateur unique : {credentials['username'] if credentials['username'] else 'Non défini'}")
                print(f"  Mot de passe unique: {'********' if credentials['password'] else 'Non défini'}")
                
                print("\n[*] Identifiants multiples configurés pour 'testcreds':")
                print(f"  Domaine            : {multi_credentials['domain'] if multi_credentials['domain'] else 'Non défini'}")
                if multi_credentials["users_file"]:
                    print(f"  Fichier utilisateurs: {multi_credentials['users_file']}")
                else:
                    print(f"  Utilisateurs (liste): {', '.join(multi_credentials['users']) if multi_credentials['users'] else 'Non défini'}")
                
                if multi_credentials["passwords_file"]:
                    print(f"  Fichier mots de passe: {multi_credentials['passwords_file']}")
                else:
                    print(f"  Mots de passe (liste): {'Présents' if multi_credentials['passwords'] else 'Non défini'}")

                if multi_credentials["hashes_file"]:
                    print(f"  Fichier hashes     : {multi_credentials['hashes_file']}")
                else:
                    print(f"  Hashes (liste)     : {'Présents' if multi_credentials['hashes'] else 'Non défini'}")

            elif command == "clear" and len(command_parts) > 1 and command_parts[1] == "creds":
                credentials["username"] = None
                credentials["password"] = None
                credentials["domain"] = None
                multi_credentials["domain"] = None
                
                multi_credentials["users"] = []
                multi_credentials["passwords"] = []
                multi_credentials["hashes"] = []
                multi_credentials["users_file"] = None
                multi_credentials["passwords_file"] = None
                multi_credentials["hashes_file"] = None
                print("[*] Tous les identifiants (uniques et multiples) ont été effacés.")
                logging.info("Tous les identifiants effacés.")
            
            elif command == "testcreds":
                run_credential_tests(target_ip, scanned_ports, multi_credentials, session)

            else:
                print(f"Commande inconnue: {command}. Tapez 'help' pour la liste des commandes.")

        except KeyboardInterrupt:
            logging.warning("Sortie demandée par l'utilisateur (Ctrl+C)")
            print("\nAu revoir ! (Ctrl+C détecté)")
            break
        except EOFError:
            logging.warning("Sortie demandée par l'utilisateur (Ctrl+D)")
            print("\nAu revoir ! (Ctrl+D détecté)")
            break
        except Exception as e:
            logging.error(f"Une erreur inattendue est survenue: {e}", exc_info=True)
            print(f"Erreur: {e}")

def load_items_from_file(filepath):
    """Charge une liste d'éléments depuis un fichier (un élément par ligne)."""
    if filepath and os.path.isfile(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Erreur lors de la lecture du fichier {filepath}: {e}")
            logging.error(f"Erreur lecture fichier {filepath}: {e}")
    return []

def run_credential_tests(target_ip, scanned_services_ports, cred_config, session):
    """
    Exécute des tentatives d'authentification sur les services détectés
    en utilisant les listes d'utilisateurs, mots de passe et hashes fournies.
    """
    logging.info(f"Lancement des tests d'identifiants sur {target_ip}")
    print(f"\n[*] Lancement des tests d'identifiants sur {target_ip}...")

    users_to_test = cred_config["users"]
    if cred_config["users_file"]:
        users_to_test.extend(load_items_from_file(cred_config["users_file"]))
    
    passwords_to_test = cred_config["passwords"]
    if cred_config["passwords_file"]:
        passwords_to_test.extend(load_items_from_file(cred_config["passwords_file"]))

    hashes_to_test = cred_config["hashes"]
    if cred_config["hashes_file"]:
        hashes_to_test.extend(load_items_from_file(cred_config["hashes_file"]))

    domain = cred_config["domain"]

    if not users_to_test:
        print("[-] Aucune liste d'utilisateurs à tester. Configurez avec 'set users' ou 'set usersfile'.")
        return
    if not passwords_to_test and not hashes_to_test:
        print("[-] Aucune liste de mots de passe ou de hashes à tester. Configurez avec 'set passwords/hashes' ou 'set passwordsfile/hashesfile'.")
        return

    successful_logins = []

    protocols_to_test_map = {
        "SMB": "smb",
        "WinRM_HTTP": "winrm",
        "WinRM_HTTPS": "winrm",
        "LDAP": "ldap",
        "LDAPS": "ldap",
        "MSSQL": "mssql",
        "RDP": "rdp",
        "SSH": "ssh",
        "FTP": "ftp",
    }

    for service_name, ports in scanned_services_ports.items():
        if not ports:
            continue
        
        nxc_protocol = protocols_to_test_map.get(service_name)
        if not nxc_protocol:
            logging.info(f"Pas de mapping nxc pour le service '{service_name}', ignoré pour testcreds.")
            continue

        print(f"\n--- Test du service: {service_name} (Protocole nxc: {nxc_protocol}) sur les ports {ports} ---")

        for user in set(users_to_test):
            if not user: continue

            for password in set(passwords_to_test):
                if not password: continue
                
                print(f"  [>] Test: {user} / {password[:2]}** (domaine: {domain if domain else 'local'}) sur {service_name}")
                cmd = [NXC_CMD, nxc_protocol, target_ip, "-u", user, "-p", password]
                if domain:
                    cmd.extend(["-d", domain])
                if nxc_protocol == "ldap" and (636 in ports or 3269 in ports):
                    cmd.append("--ssl")
                
                if nxc_protocol == "smb": cmd.append("--shares")

                output, ret_code = run_command(cmd, capture_output=True)

                if output and "(Pwn3d!)" in output:
                    success_detail = f"Service: {service_name}, User: {user}, Pass: {password}"
                    print(f"    {AnsiColors.GREEN}[+] SUCCÈS (Pwn3d!): {success_detail}{AnsiColors.ENDC}")
                    successful_logins.append(success_detail)
                elif ret_code == 0 and output and not any(err_msg in output.lower() for err_msg in ["logon failure", "authentication failed", "access denied"]):
                    if nxc_protocol == "smb" and "READ" in output or "WRITE" in output:
                         success_detail = f"Service: {service_name}, User: {user}, Pass: {password} (Accès confirmé)"
                         print(f"    {AnsiColors.GREEN}[+] SUCCÈS (Accès confirmé): {success_detail}{AnsiColors.ENDC}")
                         successful_logins.append(success_detail)

            for ntlm_hash in set(hashes_to_test):
                if not ntlm_hash: continue

                print(f"  [>] Test: {user} / Hash: {ntlm_hash[:10]}... (domaine: {domain if domain else 'local'}) sur {service_name}")
                cmd = [NXC_CMD, nxc_protocol, target_ip, "-u", user, "-H", ntlm_hash]
                if domain:
                    cmd.extend(["-d", domain])
                if nxc_protocol == "ldap" and (636 in ports or 3269 in ports):
                    cmd.append("--ssl")
                if nxc_protocol == "smb": cmd.append("--shares")

                output, ret_code = run_command(cmd, capture_output=True)

                if output and "(Pwn3d!)" in output:
                    success_detail = f"Service: {service_name}, User: {user}, Hash: {ntlm_hash}"
                    print(f"    {AnsiColors.GREEN}[+] SUCCÈS (Pwn3d! avec Hash): {success_detail}{AnsiColors.ENDC}")
                    successful_logins.append(success_detail)
                elif ret_code == 0 and output and not any(err_msg in output.lower() for err_msg in ["logon failure", "authentication failed", "access denied"]):
                    if nxc_protocol == "smb" and "READ" in output or "WRITE" in output:
                         success_detail = f"Service: {service_name}, User: {user}, Hash: {ntlm_hash} (Accès confirmé)"
                         print(f"    {AnsiColors.GREEN}[+] SUCCÈS (Accès confirmé avec Hash): {success_detail}{AnsiColors.ENDC}")
                         successful_logins.append(success_detail)


    if successful_logins:
        print("\n--- [!] Identifiants valides trouvés ---")
        for login in set(successful_logins):
            print(f"  {AnsiColors.GREEN}{login}{AnsiColors.ENDC}")
    else:
        print("\n--- [-] Aucun identifiant valide trouvé lors des tests. ---")

    logging.info(f"Tests d'identifiants terminés. Succès: {len(set(successful_logins))}")


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
    
    if not open_services_found and not any(port_info[0] for port_info in SERVICE_PORTS.values()):
        logging.warning(f"Aucun service pertinent détecté sur {args.target_ip}. L'outil interactif pourrait avoir des fonctionnalités limitées.")

    session = PromptSession(history=FileHistory('.ad_explorer_target_history'), style=cli_style)

    main_loop(args.target_ip, open_services_found, session)

    logging.info("AD Explorer terminé.") 
