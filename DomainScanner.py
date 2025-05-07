#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import socket
import subprocess
import os
import tempfile
import shutil
import sys
import re

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.validation import Validator, ValidationError
    from prompt_toolkit.styles import Style as PromptStyle
except ImportError:
    print("Erreur: La librairie 'prompt_toolkit' n'est pas installée.")
    print("Veuillez l'installer avec : pip install prompt_toolkit")
    sys.exit(1)

# --- Couleurs ANSI ---
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    NO_COLOR_MODE = False # Variable globale pour gérer le mode sans couleur

HOSTS_FILE_PATH = "/etc/hosts"
HOSTS_ENTRY_TAG = "# Ajouté par DomainDiscoverPy"

# --- Fonctions utilitaires ---
def print_info(message):
    if Colors.NO_COLOR_MODE: print(f"[*] {message}")
    else: print(f"{Colors.CYAN}[*] {message}{Colors.ENDC}")

def print_success(message):
    if Colors.NO_COLOR_MODE: print(f"[+] {message}")
    else: print(f"{Colors.GREEN}[+] {message}{Colors.ENDC}")

def print_warning(message):
    if Colors.NO_COLOR_MODE: print(f"[!] {message}")
    else: print(f"{Colors.YELLOW}[!] {message}{Colors.ENDC}")

def print_error(message):
    if Colors.NO_COLOR_MODE: print(f"[-] {message}")
    else: print(f"{Colors.RED}[-] {message}{Colors.ENDC}")

def check_tool_installed(tool_name):
    """Vérifie si un outil est installé et accessible dans le PATH."""
    if shutil.which(tool_name) is None:
        print_error(f"L'outil '{tool_name}' n'est pas installé ou n'est pas dans votre PATH.")
        print_info(f"Veuillez l'installer et réessayer.")
        if tool_name == "subfinder":
            print_info("Instructions d'installation pour Subfinder:")
            print_info("  Consultez: https://github.com/projectdiscovery/subfinder")
            print_info("  Exemple: GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder")
        elif tool_name == "httpx":
            print_info("Instructions d'installation pour Httpx:")
            print_info("  Consultez: https://github.com/projectdiscovery/httpx")
            print_info("  Exemple: GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx")
        return False
    return True

def is_sudo():
    """Vérifie si le script est exécuté avec les privilèges sudo."""
    return os.geteuid() == 0

# --- Fonctions principales ---

def reverse_dns_lookup(ip_address):
    """
    Effectue une résolution DNS inverse et demande à l'utilisateur de confirmer/fournir le domaine.
    """
    try:
        hostname, aliaslist, _ = socket.gethostbyaddr(ip_address)
        print_success(f"Nom d'hôte principal trouvé pour {ip_address}: {hostname}")
        
        potential_domains = [hostname] + aliaslist
        if aliaslist:
            print_info(f"Alias trouvés: {', '.join(aliaslist)}")

        if len(potential_domains) > 1:
            print_info("Veuillez sélectionner le domaine principal à utiliser:")
            for i, domain in enumerate(potential_domains):
                print(f"  {i+1}. {domain}")
            print(f"  {len(potential_domains)+1}. Entrer un domaine manuellement")
            
            while True:
                try:
                    choice = int(input(f"Votre choix (1-{len(potential_domains)+1}): "))
                    if 1 <= choice <= len(potential_domains):
                        return potential_domains[choice-1]
                    elif choice == len(potential_domains)+1:
                        break # Demander manuellement
                    else:
                        print_warning("Choix invalide.")
                except ValueError:
                    print_warning("Veuillez entrer un nombre.")
        else:
            confirm = input(f"Utiliser '{hostname}' comme domaine principal? (O/n/m pour manuel): ").strip().lower()
            if confirm == 'o' or confirm == '':
                return hostname
            elif confirm == 'm':
                pass # Demander manuellement
            else: # 'n' ou autre chose
                print_info("Opération annulée par l'utilisateur.")
                return None


    except socket.herror:
        print_warning(f"Impossible de trouver un enregistrement PTR pour {ip_address}.")
    except socket.gaierror:
        print_warning(f"Erreur de résolution d'adresse pour {ip_address} (nom ou service non connu).")
    
    # Si échec ou si l'utilisateur veut entrer manuellement
    manual_domain = input("Veuillez entrer le nom de domaine principal manuellement (ex: example.com): ").strip()
    if manual_domain:
        return manual_domain
    else:
        print_error("Aucun nom de domaine fourni.")
        return None

def modify_hosts_file(ip_address, domain_name, add_entry=True):
    """
    Ajoute ou supprime une entrée dans le fichier /etc/hosts.
    Nécessite les droits sudo pour modifier le fichier.
    """
    entry = f"{ip_address}\t{domain_name}\t{HOSTS_ENTRY_TAG}"
    
    if not is_sudo():
        print_warning("Permissions root requises pour modifier /etc/hosts.")
        if add_entry:
            print_info(f"Pour ajouter l'entrée manuellement, exécutez:")
            print(f"  echo \"{entry}\" | sudo tee -a {HOSTS_FILE_PATH}")
        else:
            print_info(f"Pour supprimer l'entrée manuellement, vous pouvez éditer {HOSTS_FILE_PATH} avec sudo")
            print_info(f"Ou utiliser une commande comme :")
            print(f"  sudo sed -i '/^{re.escape(ip_address)}\\s\\+{re.escape(domain_name)}\\s\\+{re.escape(HOSTS_ENTRY_TAG)}$/d' {HOSTS_FILE_PATH}")
        return False

    try:
        # Créer une sauvegarde
        backup_path = HOSTS_FILE_PATH + ".bak"
        shutil.copy2(HOSTS_FILE_PATH, backup_path)
        print_info(f"Sauvegarde de {HOSTS_FILE_PATH} créée à {backup_path}")

        with open(HOSTS_FILE_PATH, 'r') as f:
            lines = f.readlines()

        entry_exists = any(entry.strip() == line.strip() for line in lines)
        
        if add_entry:
            if entry_exists:
                print_info(f"L'entrée '{entry}' existe déjà dans {HOSTS_FILE_PATH}.")
                return True # Considéré comme un succès car l'état désiré est atteint
            
            confirm_add = input(f"Ajouter l'entrée '{entry}' à {HOSTS_FILE_PATH}? (O/n): ").strip().lower()
            if confirm_add == 'o' or confirm_add == '':
                with open(HOSTS_FILE_PATH, 'a') as f:
                    f.write(f"\n{entry}\n")
                print_success(f"Entrée ajoutée à {HOSTS_FILE_PATH}.")
                return True
            else:
                print_info("Ajout au fichier hosts annulé.")
                return False
        else: # Supprimer l'entrée
            if not entry_exists:
                # Vérifier une entrée sans le tag, au cas où
                simple_entry_exists = any(f"{ip_address}\t{domain_name}" in line for line in lines)
                if simple_entry_exists:
                     print_warning(f"L'entrée exacte '{entry}' n'a pas été trouvée, mais une entrée similaire pour {ip_address} {domain_name} pourrait exister.")
                     print_info(f"Veuillez vérifier manuellement {HOSTS_FILE_PATH}.")
                else:
                    print_info(f"L'entrée '{entry}' n'a pas été trouvée dans {HOSTS_FILE_PATH}.")
                return False

            confirm_remove = input(f"Supprimer l'entrée '{entry}' de {HOSTS_FILE_PATH}? (O/n): ").strip().lower()
            if confirm_remove == 'o' or confirm_remove == '':
                new_lines = [line for line in lines if entry.strip() != line.strip()]
                with open(HOSTS_FILE_PATH, 'w') as f:
                    f.writelines(new_lines)
                print_success(f"Entrée supprimée de {HOSTS_FILE_PATH}.")
                return True
            else:
                print_info("Suppression du fichier hosts annulée.")
                return False
                
    except Exception as e:
        print_error(f"Erreur lors de la modification de {HOSTS_FILE_PATH}: {e}")
        # Restaurer la sauvegarde en cas d'erreur
        if 'backup_path' in locals() and os.path.exists(backup_path):
            try:
                shutil.copy2(backup_path, HOSTS_FILE_PATH)
                print_info(f"Fichier {HOSTS_FILE_PATH} restauré depuis la sauvegarde.")
            except Exception as restore_e:
                print_error(f"Erreur critique lors de la restauration de la sauvegarde: {restore_e}")
        return False

def run_subfinder(domain_name):
    """Exécute subfinder pour découvrir les sous-domaines."""
    print_info(f"Lancement de Subfinder pour {Colors.YELLOW}{domain_name}{Colors.ENDC}...")
    try:
        process = subprocess.run(
            ["subfinder", "-d", domain_name, "-silent"],
            capture_output=True,
            text=True,
            check=True
        )
        subdomains = process.stdout.strip().split('\n')
        subdomains = [s for s in subdomains if s] # Enlever les lignes vides
        if subdomains:
            print_success(f"{len(subdomains)} sous-domaines trouvés par Subfinder.")
            # for sd in subdomains:
            #     print(f"  - {Colors.GREEN}{sd}{Colors.ENDC}") # Optionnel de colorer ici, le rapport final le fera
            return subdomains
        else:
            print_warning("Aucun sous-domaine trouvé par Subfinder.")
            return []
    except FileNotFoundError:
        print_error("Subfinder n'est pas installé ou n'est pas dans le PATH.")
        check_tool_installed("subfinder") # Pour afficher les instructions
        return None
    except subprocess.CalledProcessError as e:
        print_error(f"Erreur lors de l'exécution de Subfinder: {e}")
        if e.stderr:
            print_error(f"Erreur Subfinder: {e.stderr}")
        return None
    except Exception as e:
        print_error(f"Une erreur inattendue est survenue avec Subfinder: {e}")
        return None


def run_httpx(subdomains):
    """Exécute httpx pour valider les sous-domaines et obtenir des informations."""
    if not subdomains:
        print_info("Aucun sous-domaine à valider avec Httpx.")
        return None

    print_info("Lancement de Httpx pour valider les sous-domaines...")
    httpx_results = []

    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
        for subdomain in subdomains:
            tmp_file.write(subdomain + '\n')
        tmp_file_path = tmp_file.name
    
    print_info(f"Liste des sous-domaines écrite dans {tmp_file_path}")

    try:
        # httpx -l <fichier> -status-code -title -server -tech-detect -silent -json
        # On va parser la sortie texte pour simplifier, mais JSON serait plus robuste
        command = [
            "httpx", "-l", tmp_file_path,
            "-status-code", "-title", "-server", "-tech-detect",
            "-silent", "-no-color" # No color pour faciliter le parsing
        ]
        print_info(f"Exécution de la commande: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        
        print_success("Résultats de Httpx:")
        
        # Regex pour parser la sortie de httpx (simplifié, peut nécessiter ajustement)
        # Exemple de sortie: http://test.example.com [200, "Example Domain", "ECS (sjc/4E5D)", "AmazonS3,Route53"]
        regex = re.compile(r"^(https?://[^ ]+)\s*\[(\d{3}),(.*?),(.+?),(.*?)\]$")


        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line:
                continue
            
            # Appliquer la couleur basée sur le code de statut
            match = regex.match(line)
            if match:
                url, status_code_str, title, server, tech = match.groups()
                status_code = int(status_code_str)
                
                status_color = Colors.WHITE
                if 200 <= status_code < 300: status_color = Colors.GREEN
                elif 300 <= status_code < 400: status_color = Colors.YELLOW
                elif status_code == 403: status_color = Colors.RED
                elif status_code == 404: status_color = Colors.GRAY
                elif status_code >= 500: status_color = Colors.RED

                if Colors.NO_COLOR_MODE:
                    print(f"  {line}")
                else:
                    colored_status = f"{status_color}{status_code}{Colors.ENDC}"
                    print(f"  {Colors.WHITE}{url}{Colors.ENDC} [{colored_status},{Colors.CYAN}{title}{Colors.ENDC},{Colors.MAGENTA}{server}{Colors.ENDC},{Colors.BLUE}{tech}{Colors.ENDC}]")
            else:
                if Colors.NO_COLOR_MODE: print(f"  {line}")
                else: print(f"  {Colors.GRAY}{line}{Colors.ENDC}") # Ligne non parsée, afficher en gris
            
            httpx_results.append(line) # Stocker la ligne brute pour le rapport (ou la ligne colorée si on préfère)

        process.wait()
        
        if process.returncode != 0:
            print_warning(f"Httpx a terminé avec un code d'erreur {process.returncode}.")
            stderr_output = process.stderr.read()
            if stderr_output:
                print_warning(f"Erreur Httpx: {stderr_output.strip()}")
        
        if not httpx_results:
             print_warning("Aucun résultat valide retourné par Httpx.")
        
        return httpx_results

    except FileNotFoundError:
        print_error("Httpx n'est pas installé ou n'est pas dans le PATH.")
        check_tool_installed("httpx") # Pour afficher les instructions
        return None
    except Exception as e:
        print_error(f"Une erreur inattendue est survenue avec Httpx: {e}")
        return None
    finally:
        if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)
            print_info(f"Fichier temporaire {tmp_file_path} supprimé.")

class IPAddressValidator(Validator):
    def validate(self, document):
        text = document.text
        if not text: # Permettre de passer si vide pour utiliser une valeur par défaut potentielle ou re-demander
            return
        # Simple validation pour IPv4, peut être étendue pour IPv6 ou noms d'hôte si nécessaire
        parts = text.split('.')
        if len(parts) == 4:
            for item in parts:
                if not item.isdigit() or not 0 <= int(item) <= 255:
                    raise ValidationError(message='Adresse IP invalide.', cursor_position=len(text))
        else:
            # Permettre les noms d'hôte qui pourraient être résolus plus tard
            # ou considérer ceci comme une erreur si seule une IP est attendue.
            # Pour ce script, une IP est attendue pour le reverse DNS initial.
            # On pourrait ajouter une résolution DNS ici pour valider un nom d'hôte.
            pass # Accepter les noms d'hôtes pour l'instant, la logique métier gérera la résolution

def get_boolean_input(session, prompt_message, default=True):
    completer = WordCompleter(['oui', 'non', 'o', 'n'], ignore_case=True)
    while True:
        try:
            text = session.prompt(
                prompt_message,
                completer=completer,
                auto_suggest=AutoSuggestFromHistory(),
                default='o' if default else 'n'
            ).strip().lower()
            if text in ['oui', 'o']:
                return True
            elif text in ['non', 'n']:
                return False
            else:
                print_warning("Veuillez répondre par 'oui' (o) ou 'non' (n).")
        except KeyboardInterrupt:
            print_info("\nSaisie annulée.")
            return None # Ou lever l'exception pour quitter
        except EOFError:
            print_info("\nSaisie annulée (EOF).")
            return None # Ou lever l'exception pour quitter


def run_domain_scan_logic(ip_address, no_color_flag):
    """
    Encapsule la logique principale du scan de domaine.
    Prend les paramètres nécessaires en arguments.
    """
    Colors.NO_COLOR_MODE = no_color_flag
    
    print_info(f"Adresse IP cible: {Colors.YELLOW}{ip_address}{Colors.ENDC}")

    if not check_tool_installed("subfinder") or not check_tool_installed("httpx"):
        return # Les messages d'erreur sont déjà affichés par check_tool_installed

    domain_name = reverse_dns_lookup(ip_address)
    if not domain_name:
        print_error("Impossible de continuer sans nom de domaine.")
        return
    
    print_success(f"Nom de domaine principal sélectionné: {Colors.GREEN}{domain_name}{Colors.ENDC}")

    hosts_modified = False
    if modify_hosts_file(ip_address, domain_name, add_entry=True):
        hosts_modified = True

    subdomains_found = run_subfinder(domain_name)
    httpx_output = None

    if subdomains_found:
        httpx_output = run_httpx(subdomains_found)
    else:
        print_info("Aucun sous-domaine trouvé, Httpx ne sera pas exécuté.")

    # Rapport final
    print("\n--- Rapport Final ---")
    print(f"Adresse IP Cible: {Colors.YELLOW}{ip_address}{Colors.ENDC}")
    print(f"Nom de Domaine Principal: {Colors.GREEN}{domain_name}{Colors.ENDC}")
    
    if hosts_modified:
        print_info(f"Le fichier {HOSTS_FILE_PATH} a été configuré pour {ip_address} -> {domain_name}.")
    elif is_sudo():
         print_info(f"L'utilisateur a choisi de ne pas modifier {HOSTS_FILE_PATH} ou l'entrée existait déjà.")
    else:
        print_info(f"Le fichier {HOSTS_FILE_PATH} n'a pas été modifié (privilèges root non détectés ou action non confirmée).")

    if subdomains_found:
        print_success(f"Sous-domaines découverts par Subfinder ({len(subdomains_found)}):")
        for sd in subdomains_found:
            if Colors.NO_COLOR_MODE: print(f"  - {sd}")
            else: print(f"  - {Colors.GREEN}{sd}{Colors.ENDC}")
    else:
        print_warning("Aucun sous-domaine n'a été découvert.")

    if httpx_output:
        print_success("Informations Httpx (re-traitées pour couleur):")
        regex_report = re.compile(r"^(https?://[^ ]+)\s*\[(\d{3}),(.*?),(.+?),(.*?)\]$")
        for res_line in httpx_output:
            match = regex_report.match(res_line)
            if match:
                url, status_code_str, title, server, tech = match.groups()
                status_code = int(status_code_str)
                
                status_color = Colors.WHITE
                if 200 <= status_code < 300: status_color = Colors.GREEN
                elif 300 <= status_code < 400: status_color = Colors.YELLOW
                elif status_code == 403: status_color = Colors.RED
                elif status_code == 404: status_color = Colors.GRAY
                elif status_code >= 500: status_color = Colors.RED

                if Colors.NO_COLOR_MODE:
                    print(f"  {res_line}")
                else:
                    colored_status = f"{status_color}{status_code}{Colors.ENDC}"
                    print(f"  {Colors.WHITE}{url}{Colors.ENDC} [{colored_status},{Colors.CYAN}{title}{Colors.ENDC},{Colors.MAGENTA}{server}{Colors.ENDC},{Colors.BLUE}{tech}{Colors.ENDC}]")
            else:
                if Colors.NO_COLOR_MODE: print(f"  {res_line}")
                else: print(f"  {Colors.GRAY}{res_line}{Colors.ENDC}") # Ligne non parsée
    elif subdomains_found:
        print_warning("Aucune information n'a été collectée par Httpx pour les sous-domaines trouvés.")

    if hosts_modified and is_sudo():
        print_info(f"\nL'entrée {ip_address} {domain_name} a été ajoutée à {HOSTS_FILE_PATH}.")
        if input("Souhaitez-vous supprimer cette entrée de /etc/hosts maintenant? (O/n): ").strip().lower() in ['o', '']:
            modify_hosts_file(ip_address, domain_name, add_entry=False)
        else:
            print_info(f"L'entrée n'a pas été supprimée. Vous pouvez la supprimer manuellement plus tard.")
    elif hosts_modified and not is_sudo():
        print_info(f"\nSi vous avez ajouté l'entrée à {HOSTS_FILE_PATH} manuellement, n'oubliez pas de la nettoyer si nécessaire.")

    print_info("Fin du scan de domaine.")


def interactive_main():
    session = PromptSession(history=FileHistory('.domainscanner_history'))
    
    # Style pour prompt_toolkit (optionnel, peut être étendu)
    style = PromptStyle.from_dict({
        'prompt': 'ansiblue bold',
        '': '#ffffff', # Default text
    })

    print_info("Bienvenue dans DomainScanner Interactif!")
    print_info("Tapez Ctrl-C ou Ctrl-D pour quitter à tout moment lors d'une invite.")

    while True:
        try:
            target_ip = session.prompt(
                "Entrez l'adresse IP cible: ",
                validator=IPAddressValidator(),
                validate_while_typing=False,
                auto_suggest=AutoSuggestFromHistory(),
                style=style
            ).strip()
            if not target_ip:
                print_warning("L'adresse IP est requise.")
                continue

            use_color_input = get_boolean_input(session, "Activer la sortie colorée? (O/n): ", default=True)
            if use_color_input is None: # Ctrl-C/D dans get_boolean_input
                break 
            no_color = not use_color_input

            run_domain_scan_logic(target_ip, no_color)

        except KeyboardInterrupt:
            print_info("\nScan interrompu par l'utilisateur.")
            break
        except EOFError:
            print_info("\nFin de la saisie. Au revoir!")
            break
        
        try:
            if session.prompt("Lancer un autre scan? (O/n): ", default="o").strip().lower() not in ['o', 'oui']:
                break
        except (KeyboardInterrupt, EOFError):
            break
            
    print_info("DomainScanner Interactif terminé.")

if __name__ == "__main__":
    # Commenter ou supprimer l'ancien argparse
    # parser = argparse.ArgumentParser(description="Découverte de sous-domaines à partir d'une adresse IP.")
    # parser.add_argument("ip_address", help="L'adresse IP cible.")
    # parser.add_argument("--no-color", action="store_true", help="Désactiver la sortie colorée.")
    # args = parser.parse_args()
    #
    # if args.no_color:
    #     Colors.NO_COLOR_MODE = True
    #
    # run_domain_scan_logic(args.ip_address, args.no_color)
    interactive_main() 
