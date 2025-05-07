import requests
import argparse
import threading
import time
import random
import os
import datetime
from queue import Queue
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser
import socket
import sys
import subprocess
import shutil
import json

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter, PathCompleter
    from prompt_toolkit.validation import Validator, ValidationError
    from prompt_toolkit.styles import Style as PromptStyle
except ImportError:
    print("Erreur: La librairie 'prompt_toolkit' n'est pas installée.")
    print("Veuillez l'installer avec : pip install prompt_toolkit")
    sys.exit(1)

# --- Configuration Globale ---
DEFAULT_THREADS = 10
DEFAULT_WORDLIST = "wordlist.txt"
DEFAULT_EXTENSIONS_FILE = "extensions.txt"
DEFAULT_USER_AGENTS_FILE = "user_agents.txt"
REQUEST_TIMEOUT = 10 # secondes

# --- Couleurs ANSI ---
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    LIGHT_RED = '\033[1;31m' # Pour 403 par exemple
    GRAY = '\033[90m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'

# Listes pour stocker les résultats et les informations
found_results = []
total_requests_made = 0
lock = threading.Lock()
print_lock = threading.Lock()

# --- Agents Utilisateurs ---
USER_AGENTS = []

def load_user_agents(filename=DEFAULT_USER_AGENTS_FILE):
    """Charge les agents utilisateurs depuis un fichier."""
    global USER_AGENTS
    try:
        with open(filename, 'r') as f:
            USER_AGENTS = [line.strip() for line in f if line.strip()]
        if not USER_AGENTS:
            print(f"[!] Attention: Le fichier d'agents utilisateurs '{filename}' est vide. Utilisation d'un agent par défaut.")
            USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"]
    except FileNotFoundError:
        print(f"[!] Erreur: Fichier d'agents utilisateurs '{filename}' non trouvé. Utilisation d'un agent par défaut.")
        USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"]

def get_random_user_agent():
    """Retourne un agent utilisateur aléatoire."""
    return random.choice(USER_AGENTS) if USER_AGENTS else "Python Content Scanner"

# --- Détection du Serveur et Adaptation des Extensions ---
def detect_server_and_cms(target_url):
    """
    Effectue une requête HEAD pour détecter le type de serveur et potentiellement des CMS.
    Retourne un dictionnaire avec les informations du serveur et les CMS détectés.
    """
    server_info = {"type": "Unknown", "details": "", "cms": []}
    headers = {'User-Agent': get_random_user_agent()}
    try:
        response = requests.head(target_url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if 'Server' in response.headers:
            server_header = response.headers['Server']
            server_info["details"] = server_header
            if "iis" in server_header.lower():
                server_info["type"] = "IIS"
            elif "apache" in server_header.lower():
                server_info["type"] = "Apache"
            elif "nginx" in server_header.lower():
                server_info["type"] = "Nginx"
            # Ajout de détections basiques de CMS via les en-têtes (peut être étendu)
            if "X-Powered-By" in response.headers:
                if "ASP.NET" in response.headers["X-Powered-By"]:
                     if server_info["type"] == "Unknown": server_info["type"] = "IIS" # Souvent lié
                if "PHP" in response.headers["X-Powered-By"]:
                     if server_info["type"] == "Unknown": server_info["type"] = "Apache/Nginx" # Souvent lié
            if "X-Drupal-Cache" in response.headers or "X-Generator" in response.headers and "Drupal" in response.headers["X-Generator"]:
                server_info["cms"].append("Drupal")
            if response.headers.get("Link") and "wp.me" in response.headers.get("Link", ""): # WordPress.com hosted
                 server_info["cms"].append("WordPress")
            # On pourrait aussi faire une requête GET sur la page d'accueil et chercher des motifs
            # comme <meta name="generator" content="WordPress X.Y.Z" />
            # ou des chemins spécifiques comme /wp-includes/js/wp-emoji-release.min.js

    except requests.RequestException as e:
        with print_lock:
            print(f"[!] Erreur lors de la détection du serveur sur {target_url}: {e}")
    return server_info

def adapt_extensions(base_extensions, server_info):
    """Adapte la liste d'extensions en fonction du serveur et des CMS détectés."""
    adapted_extensions = list(base_extensions) # Copie pour ne pas modifier l'original
    specific_extensions = []

    if server_info["type"] == "IIS":
        specific_extensions.extend(['.aspx', '.asp', '.asmx', '.config', '.dll', '.ashx', '.svc'])
    elif server_info["type"] in ["Apache", "Nginx"]:
        specific_extensions.extend(['.php', '.php3', '.php4', '.php5', '.phtml', '.py', '.rb', '.pl', '.cgi', '.htaccess'])

    if "WordPress" in server_info["cms"]:
        specific_extensions.extend([
            'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.txt',
            '.env', 'debug.log', 'xmlrpc.php'
        ])
        # Ajouter des chemins spécifiques à WordPress à la wordlist serait aussi une bonne idée
    if "Joomla" in server_info["cms"]: # Exemple, détection non implémentée
        specific_extensions.extend(['configuration.php', 'configuration.php.bak'])
    if "Drupal" in server_info["cms"]:
        specific_extensions.extend(['sites/default/settings.php'])


    # Ajoute les extensions spécifiques au début pour les tester en priorité,
    # tout en évitant les doublons et en conservant les extensions de base.
    final_extensions = [ext for ext in specific_extensions if ext not in adapted_extensions] + adapted_extensions
    
    # S'assurer que les extensions commencent par un point si ce n'est pas un nom de fichier complet
    final_extensions = [ext if ext.startswith('.') or '/' in ext else '.' + ext for ext in final_extensions]
    # Pour les noms de fichiers complets (comme wp-config.php), on ne veut pas de point devant
    final_extensions = [ext[1:] if ext.startswith('.') and not ext[1:].startswith('.') and ext.count('.') == 1 and not any(c.islower() for c in ext[1:]) else ext for ext in final_extensions]
    # Correction pour les noms de fichiers complets qui pourraient avoir un point en trop
    final_extensions = [ext.replace('..', '.') for ext in final_extensions]
    final_extensions = list(dict.fromkeys(final_extensions)) # Enlever les doublons en conservant l'ordre

    return final_extensions

# --- Gestion de robots.txt ---
class RobotsManager:
    def __init__(self, target_url):
        self.rp = RobotFileParser()
        self.target_base_url = urljoin(target_url, '/')
        robots_url = urljoin(self.target_base_url, "robots.txt")
        self.rp.set_url(robots_url)
        try:
            self.rp.read()
        except Exception as e:
            with print_lock:
                print(f"[!] Avertissement: Impossible de lire ou parser robots.txt depuis {robots_url}: {e}")

    def can_fetch(self, user_agent, path):
        """Vérifie si le chemin est autorisé par robots.txt."""
        full_url = urljoin(self.target_base_url, path)
        return self.rp.can_fetch(user_agent, full_url)

# --- Fonctions Utilitaires (pour les commandes externes) ---
def check_command_exists(command):
    """Vérifie si une commande externe existe dans le PATH."""
    if shutil.which(command) is None:
        print(f"{Colors.RED}[!] Attention: La commande '{command}' est introuvable. Certaines fonctionnalités pourraient ne pas être disponibles.{Colors.ENDC}")
        return False
    return True

def run_command(command_list, capture_output=True, text=True, shell=False):
    """Exécute une commande externe et retourne sa sortie et son code de retour."""
    command_str = command_list if shell else " ".join(command_list)
    print(f"[*] Exécution: {command_str}")
    try:
        process = subprocess.run(
            command_list,
            capture_output=capture_output,
            text=text,
            shell=shell,
            check=False # Ne pas lever d'exception pour les codes de retour non nuls
        )
        return process.stdout, process.stderr, process.returncode
    except FileNotFoundError:
        print(f"{Colors.RED}[-] Erreur: Commande '{command_list[0]}' introuvable.{Colors.ENDC}")
        return None, "Commande non trouvée", -1
    except Exception as e:
        print(f"{Colors.RED}[-] Erreur lors de l'exécution de '{command_str}': {e}{Colors.ENDC}")
        return None, str(e), -1

# --- Découverte des Services Web ---
DEFAULT_WEB_PORTS = [80, 443, 8000, 8080, 8081, 8443, 8888]

def discover_web_services(target_host, ports_to_scan=None, no_color_mode=False):
    """Scanne les ports spécifiés pour des services web HTTP/HTTPS."""
    if ports_to_scan is None:
        ports_to_scan = DEFAULT_WEB_PORTS
    
    active_services = []
    print(f"[*] Scan des ports web sur {target_host}...")

    for port in ports_to_scan:
        try:
            with socket.create_connection((target_host, port), timeout=1):
                # Port ouvert, essayons de déterminer HTTP/HTTPS
                # Simplification: 443 est HTTPS, 80 est HTTP. Pour les autres, on essaie HTTP d'abord.
                # Une détection robuste nécessiterait d'envoyer une requête ou de tenter une connexion SSL.
                if port == 443 or port == 8443 or port == 3001: # Ports typiquement HTTPS
                    protocol = "https"
                else:
                    protocol = "http" # Par défaut HTTP pour les autres

                # Tentative de confirmation HTTPS pour les ports non standards
                if protocol == "http" and port not in [80, 8000, 8080]: # Éviter de tester SSL sur des ports HTTP connus
                    try:
                        context = ssl.create_default_context()
                        with socket.create_connection((target_host, port), timeout=1) as sock:
                            with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                                protocol = "https" # Connexion SSL réussie
                                print(f"  {Colors.GREEN if not no_color_mode else ''}[+] Port {port} ({protocol.upper()}) semble être HTTPS.{Colors.ENDC if not no_color_mode else ''}")
                    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
                        print(f"  {Colors.YELLOW if not no_color_mode else ''}[*] Port {port} ({protocol.upper()}) semble être HTTP (SSL a échoué ou timeout).{Colors.ENDC if not no_color_mode else ''}")
                        pass # Reste HTTP

                base_url = f"{protocol}://{target_host}:{port}"
                # Éviter les ports standards dans l'URL si possible
                if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
                    base_url = f"{protocol}://{target_host}"
                
                active_services.append(base_url)
                if not no_color_mode:
                    print(f"  {Colors.GREEN}[+] Service web détecté sur: {base_url}{Colors.ENDC}")
                else:
                    print(f"  [+] Service web détecté sur: {base_url}")

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass # Port non ouvert ou non joignable
    
    if not active_services and not no_color_mode:
        print(f"{Colors.YELLOW}[-] Aucun service web actif trouvé sur les ports scannés de {target_host}.{Colors.ENDC}")
    elif not active_services and no_color_mode:
        print(f"[-] Aucun service web actif trouvé sur les ports scannés de {target_host}.")

    return active_services

# --- Exécution de Feroxbuster ---
def run_feroxbuster(target_url, no_color_mode=False):
    """Exécute Feroxbuster sur l'URL cible et retourne les URLs 200 OK."""
    global found_results
    if not check_command_exists("feroxbuster"):
        return []

    print(f"[*] Lancement de Feroxbuster sur {target_url}...")
    # Utiliser un fichier de sortie temporaire pour les résultats JSON
    # Nettoyer le nom de domaine pour le nom de fichier
    parsed_url = urlparse(target_url)
    safe_filename = f"ferox_{parsed_url.netloc.replace(':', '_')}_{parsed_url.scheme}.json"
    
    # Commande Feroxbuster : -u URL, -C 200 (codes de statut), -o fichier_json, -k (ignorer erreurs SSL), -q (silencieux)
    # --json pour une sortie structurée facile à parser
    # -d 1 pour limiter la profondeur initiale, on peut l'augmenter si besoin.
    # On peut ajouter -w <wordlist> si on veut une wordlist spécifique pour feroxbuster.
    cmd = ["feroxbuster", "-u", target_url, "--status-codes", "200", "--json", "-o", safe_filename, "-k", "-q", "--no-state"]
    
    stdout, stderr, ret_code = run_command(cmd, capture_output=False) # Feroxbuster gère sa propre sortie

    ferox_found_urls = []
    try:
        if os.path.exists(safe_filename):
            with open(safe_filename, 'r') as f:
                for line in f: # Feroxbuster avec --json écrit une ligne JSON par résultat
                    try:
                        result = json.loads(line)
                        if result.get("type") == "response" and result.get("status") == 200:
                            url = result.get("url")
                            if url:
                                ferox_found_urls.append(url)
                                if not no_color_mode:
                                    print(f"  {Colors.GREEN}[FEROXBUSTER 200] {url}{Colors.ENDC}")
                                else:
                                    print(f"  [FEROXBUSTER 200] {url}")
                                # Ajout aux résultats globaux
                                found_results.append({
                                    'url': url,
                                    'status': 200,
                                    'length': result.get("content_length", "N/A"),
                                    'source': 'feroxbuster'
                                })
                    except json.JSONDecodeError:
                        # Ignorer les lignes qui ne sont pas du JSON valide (ex: résumé)
                        pass
            os.remove(safe_filename) # Nettoyer le fichier temporaire
    except Exception as e:
        if not no_color_mode:
            print(f"{Colors.RED}[!] Erreur lors de la lecture des résultats de Feroxbuster: {e}{Colors.ENDC}")
        else:
            print(f"[!] Erreur lors de la lecture des résultats de Feroxbuster: {e}")

    if not ferox_found_urls and not no_color_mode:
        print(f"{Colors.YELLOW}[-] Feroxbuster n'a trouvé aucun résultat 200 OK pour {target_url}.{Colors.ENDC}")
    elif not ferox_found_urls and no_color_mode:
         print(f"[-] Feroxbuster n'a trouvé aucun résultat 200 OK pour {target_url}.")
    return ferox_found_urls

# --- Logique de Scan ---
def scan_worker(target_url, path_queue, extensions, stealth_mode, stealth_delay, robots_manager, user_agent_for_robots):
    """Travailleur qui prend des chemins de la file et les scanne."""
    global total_requests_made, found_results

    s = requests.Session() # Utiliser une session pour la persistance des connexions (si applicable)

    while not path_queue.empty():
        try:
            word = path_queue.get_nowait()
        except Exception: # queue.Empty n'est pas toujours levé comme attendu avec get_nowait dans certains contextes
            return

        # Construire le chemin de base (sans extension)
        base_path_to_check = f"{target_url.rstrip('/')}/{word}"

        # 1. Vérifier le chemin/répertoire sans extension
        if not stealth_mode or (robots_manager and robots_manager.can_fetch(user_agent_for_robots, word)):
            make_request(s, base_path_to_check, stealth_mode, stealth_delay, word, "")
        
        # 2. Vérifier avec les extensions
        for ext in extensions:
            # Si l'extension est un nom de fichier complet (ex: wp-config.php),
            # elle doit être testée à la racine du mot (qui pourrait être un répertoire)
            if not ext.startswith('.'): 
                path_to_check = f"{target_url.rstrip('/')}/{word}/{ext.lstrip('/')}"
            else: # Extension classique
                path_to_check = f"{target_url.rstrip('/')}/{word}{ext}"
            
            # Construire le chemin relatif pour robots.txt
            relative_path_for_robots = f"{word}{ext}" if ext.startswith('.') else f"{word}/{ext.lstrip('/')}"

            if not stealth_mode or (robots_manager and robots_manager.can_fetch(user_agent_for_robots, relative_path_for_robots)):
                make_request(s, path_to_check, stealth_mode, stealth_delay, word, ext)
            else:
                with print_lock:
                    print(f"[*] Ignoré par robots.txt: {path_to_check}")
        
        path_queue.task_done()

def make_request(session, url_to_check, stealth_mode, stealth_delay, original_word, original_ext):
    """Effectue une requête HTTP et gère la réponse."""
    global total_requests_made, found_results
    
    headers = {'User-Agent': get_random_user_agent()}
    
    if stealth_mode and stealth_delay > 0:
        time.sleep(random.uniform(stealth_delay * 0.5, stealth_delay * 1.5))

    try:
        with lock:
            total_requests_made += 1
        
        response = session.get(url_to_check, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True, stream=True)
        response.close()

        status_code = response.status_code
        content_length = response.headers.get('Content-Length', 'N/A')

        color = Colors.WHITE
        if 200 <= status_code < 300:
            color = Colors.GREEN
        elif 300 <= status_code < 400:
            color = Colors.YELLOW
        elif status_code == 403:
            color = Colors.LIGHT_RED
        elif status_code == 401:
            color = Colors.MAGENTA
        elif status_code == 404:
            color = Colors.GRAY
        elif status_code >= 500:
            color = Colors.RED

        with print_lock:
            # Affichage plus concis, on a déjà le contexte du service
            status_colored = f"{color}{status_code}{Colors.ENDC}"
            path_segment = urlparse(url_to_check).path
            print(f"  [{status_colored}] {path_segment} (Longueur: {content_length})")

        if 200 <= status_code < 300 or status_code in [401, 403]: # Sauvegarder aussi 401/403
            with lock:
                found_results.append({
                    'url': url_to_check,
                    'status': status_code,
                    'length': content_length,
                    'source': 'wordlist' # Ajout de la source
                })
    except requests.exceptions.RequestException:
        pass

# --- Gestion des Résultats ---
def save_results(results, target_domain):
    """Sauvegarde les résultats trouvés dans des fichiers par extension."""
    if not results:
        return []

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = f"results_{target_domain}_{timestamp}"
    os.makedirs(results_dir, exist_ok=True)

    organized_results = {}
    for res in results:
        if res['status'] == 200:
            ext = res['ext'].replace('.', '') if res['ext'] and res['ext'].startswith('.') else 'no_ext'
            if not ext: # Pour les cas comme /admin (pas d'extension mais trouvé)
                # On essaie de deviner à partir de l'URL si c'est un fichier connu
                parsed_url_path = urlparse(res['url']).path
                _root, file_ext = os.path.splitext(parsed_url_path)
                if file_ext:
                    ext = file_ext.replace('.', '')
                else: # C'est probablement un répertoire ou un fichier sans extension visible
                    ext = "directory_or_no_ext"


            if ext not in organized_results:
                organized_results[ext] = []
            organized_results[ext].append(res['url'])

    output_files = []
    for ext, urls in organized_results.items():
        if urls:
            filename = os.path.join(results_dir, f"{ext}_found.txt")
            with open(filename, 'w') as f:
                for url in urls:
                    f.write(url + "\n")
            output_files.append(filename)
    
    return output_files, results_dir

# --- Fonction Principale (Modifiée) ---
def main():
    global total_requests_made, found_results, USER_AGENTS # USER_AGENTS est global

    parser = argparse.ArgumentParser(description="Outil de découverte de contenu web automatisé et intelligent.")
    # L'argument principal est maintenant l'hôte/IP, pas une URL complète.
    parser.add_argument("target_host", help="Hôte cible (ex: example.com ou 192.168.1.10)")
    parser.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_WEB_PORTS)),
                        help=f"Liste de ports web à scanner, séparés par des virgules (défaut: {','.join(map(str, DEFAULT_WEB_PORTS))})")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help=f"Chemin vers la wordlist (défaut: {DEFAULT_WORDLIST})")
    parser.add_argument("-x", "--extensions", default=DEFAULT_EXTENSIONS_FILE, help=f"Chemin vers le fichier d'extensions (défaut: {DEFAULT_EXTENSIONS_FILE})")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Nombre de threads (défaut: {DEFAULT_THREADS})")
    parser.add_argument("-s", "--stealth", action="store_true", help="Activer le mode furtif (délais, user-agents aléatoires, respect de robots.txt)")
    parser.add_argument("--stealth-delay", type=float, default=1.0, help="Délai moyen en secondes entre les requêtes en mode furtif (défaut: 1.0s)")
    parser.add_argument("--user-agents", default=DEFAULT_USER_AGENTS_FILE, help=f"Fichier des agents utilisateurs (défaut: {DEFAULT_USER_AGENTS_FILE})")
    parser.add_argument("--no-color", action="store_true", help="Désactiver la sortie colorée.")

    args = parser.parse_args()

    if args.no_color:
        for attr in dir(Colors):
            if not callable(getattr(Colors, attr)) and not attr.startswith("__"):
                setattr(Colors, attr, "")
    
    # Charger les user agents une fois globalement
    load_user_agents(args.user_agents)

    print("--- Configuration Globale du Scan ---")
    print(f"[*] Hôte Cible: {Colors.CYAN if not args.no_color else ''}{args.target_host}{Colors.ENDC if not args.no_color else ''}")
    print(f"[*] Mode: {Colors.YELLOW}{'Furtif' if args.stealth else 'Agressif'}{Colors.ENDC}")
    print(f"[*] Threads: {Colors.YELLOW}{args.threads}{Colors.ENDC}")
    print(f"[*] Wordlist: {Colors.YELLOW}{args.wordlist}{Colors.ENDC}")
    print(f"[*] Fichier d'extensions: {Colors.YELLOW}{args.extensions}{Colors.ENDC}")
    if args.stealth:
        print(f"[*] Délai furtif moyen: {Colors.YELLOW}{args.stealth_delay}s{Colors.ENDC}")
        print(f"[*] Fichier User-Agents: {Colors.YELLOW}{args.user_agents}{Colors.ENDC}")
    print("-----------------------------------\n")

    # 1. Découverte des services web sur l'hôte cible
    try:
        ports_to_scan_list = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        print(f"{Colors.RED if not args.no_color else ''}[!] Format de liste de ports invalide. Utilisez des nombres séparés par des virgules.{Colors.ENDC if not args.no_color else ''}")
        sys.exit(1)
        
    web_service_urls = discover_web_services(args.target_host, ports_to_scan_list, args.no_color)

    if not web_service_urls:
        print(f"[-] Aucun service web trouvé sur {args.target_host} avec les ports spécifiés. Arrêt.")
        return

    start_time_global = time.time()
    total_requests_made = 0 # Réinitialiser le compteur global
    found_results = [] # Réinitialiser les résultats globaux

    for service_url in web_service_urls:
        print(f"\n--- Scan du Service Web: {Colors.MAGENTA if not args.no_color else ''}{service_url}{Colors.ENDC if not args.no_color else ''} ---")
        service_start_time = time.time()

        # 2. Exécution de Feroxbuster pour ce service
        run_feroxbuster(service_url, args.no_color) # Les résultats sont ajoutés à found_results globalement

        # 3. Exécution du scan par wordlist pour ce service
        perform_wordlist_scan_for_service(
            service_url,
            args.wordlist,
            args.extensions,
            args.threads,
            args.stealth,
            args.stealth_delay,
            args.user_agents, # Déjà chargé, mais passé pour info ou rechargement si besoin
            args.no_color
        )
        service_end_time = time.time()
        print(f"[*] Temps pour le service {service_url}: {Colors.YELLOW if not args.no_color else ''}{service_end_time - service_start_time:.2f}s{Colors.ENDC if not args.no_color else ''}")


    end_time_global = time.time()
    scan_duration_global = end_time_global - start_time_global

    print("\n--- Scan Global Terminé ---")
    print(f"[*] Temps total du scan: {Colors.YELLOW if not args.no_color else ''}{scan_duration_global:.2f} secondes{Colors.ENDC if not args.no_color else ''}")
    print(f"[*] Hôte Cible: {Colors.CYAN if not args.no_color else ''}{args.target_host}{Colors.ENDC if not args.no_color else ''}")
    print(f"[*] Requêtes totales (wordlist scan): {Colors.YELLOW if not args.no_color else ''}{total_requests_made}{Colors.ENDC if not args.no_color else ''}") # Feroxbuster a son propre comptage
    
    # Filtrer les résultats 200 OK pour le rapport principal
    # On pourrait aussi vouloir lister les 401/403 séparément.
    final_results_200_or_interesting = [r for r in found_results if r['status'] == 200 or r['status'] == 401 or r['status'] == 403]
    
    print(f"[*] Nombre total de résultats intéressants (200, 401, 403): {Colors.GREEN if not args.no_color else ''}{len(final_results_200_or_interesting)}{Colors.ENDC if not args.no_color else ''}")

    if final_results_200_or_interesting:
        # La sauvegarde doit maintenant gérer le fait que les résultats proviennent de différents services
        # et potentiellement de différentes sources (ferox, wordlist).
        # Le nom de fichier de sauvegarde pourrait inclure l'hôte cible.
        output_files, results_dir_path = save_results(final_results_200_or_interesting, args.target_host.replace('.', '_'))
        if output_files:
            print(f"[*] Résultats sauvegardés dans le répertoire: {Colors.GREEN if not args.no_color else ''}{results_dir_path}{Colors.ENDC if not args.no_color else ''}")
            for f_name in output_files:
                print(f"    - {os.path.basename(f_name)}")
        else:
            print("[*] Aucun fichier de résultat n'a été créé.")
    else:
        print("[*] Aucun résultat intéressant (200, 401, 403) trouvé globalement.")

    # Les informations serveur sont maintenant par service, affichées dans perform_wordlist_scan_for_service
    # On pourrait faire un résumé ici si nécessaire.

if __name__ == "__main__":
    # Ajout pour la détection SSL dans discover_web_services
    import ssl
    main()
