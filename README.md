# Suite d'Outils d'Exploration et de Reconnaissance en Sécurité

Cette collection d'outils Python est conçue pour assister dans les phases de reconnaissance et d'exploration lors d'audits de sécurité, avec un accent particulier sur les environnements Active Directory et la découverte d'informations sur des cibles web et réseau.

## Prérequis Généraux

*   **Python :** Version 3.6 ou ultérieure.
*   **pip :** L'installeur de paquets Python (généralement inclus avec Python).
*   **Outils Externes :** Plusieurs scripts dépendent d'outils externes qui doivent être installés et accessibles via le PATH de votre système. Les instructions spécifiques sont détaillées pour chaque outil.

## Installation des Dépendances Python Communes

Certaines librairies Python sont requises par un ou plusieurs outils de cette suite. Vous pouvez les installer via pip :

pip install prompt_toolkit requests

## Description des Outils

### 1. AD Explorer (`ad_explorer.py`)

*   **Description :**
    Outil en ligne de commande (CLI) interactif conçu pour l'exploration des services Active Directory (SMB, LDAP, RPC, etc.) à partir d'une adresse IP cible. Il intègre des fonctionnalités de scan de ports, d'énumération de services, et un mode dédié à la découverte d'utilisateurs en s'appuyant sur des outils externes reconnus.
*   **Dépendances Spécifiques :**
    *   **Python :** `prompt_toolkit` (installé via la commande ci-dessus).
    *   **Externes :**
        *   `netexec` (nxc)
        *   `rpcclient` (inclus dans la suite Samba)
        *   `kerbrute`
*   **Utilisation :**
    ```bash
    python ad_explorer.py <adresse_ip_cible>
    ```
    Après le scan initial des services, une interface interactive vous permet de choisir les actions à effectuer. Tapez `help` dans l'interface pour la liste des commandes.
*   **Fonctionnalités Clés :**
    *   Scan de ports rapide pour les services AD courants.
    *   Interface CLI interactive avec historique et autocomplétion.
    *   Exploration détaillée des services SMB, LDAP, RPC en utilisant `nxc` et `rpcclient`.
    *   Mode "Découverte d'Utilisateurs" utilisant SMB (session null), LDAP (anonyme), et `kerbrute`.
    *   Gestion basique des identifiants pour la session.
    *   Journalisation des actions.

### 2. Domain Discover (`domain_discover.py`)

*   **Description :**
    Script permettant la découverte de sous-domaines associés à une adresse IP donnée. Il utilise la résolution DNS inverse, puis s'appuie sur `subfinder` pour l'énumération des sous-domaines et `httpx` pour vérifier leur statut HTTP/HTTPS et collecter des informations basiques. Il peut également aider à configurer le fichier `/etc/hosts` localement pour faciliter l'accès.
*   **Dépendances Spécifiques :**
    *   **Python :** Aucune librairie non standard (utilise les modules intégrés).
    *   **Externes :**
        *   `subfinder`
        *   `httpx`
    *   **Privilèges :** Nécessite des privilèges `sudo` (ou administrateur) pour modifier le fichier `/etc/hosts`.
*   **Utilisation :**
    ```bash
    python domain_discover.py <adresse_ip_cible>
    ```
    Le script vous guidera pour confirmer le domaine principal et pour la modification optionnelle du fichier hosts.
*   **Fonctionnalités Clés :**
    *   Résolution DNS inverse pour identifier un nom de domaine initial.
    *   Énumération de sous-domaines avec `subfinder`.
    *   Vérification HTTP/HTTPS et collecte d'informations (titre, code statut, serveur, technologies) avec `httpx`.
    *   Assistance pour l'ajout/suppression d'entrées dans `/etc/hosts`.

### 3. DirScanner (`DirScanner/DIRScanner.py`)

*   **Description :**
    Outil de découverte de contenu web (fichiers et répertoires cachés) basé sur des listes de mots (wordlists). Il est multithread, peut opérer en mode furtif (respect de `robots.txt`, délais aléatoires, user-agents variés) et adapte les extensions de fichiers recherchées en fonction du serveur web détecté.
*   **Dépendances Spécifiques :**
    *   **Python :** `requests` (installé via la commande ci-dessus).
    *   **Fichiers de configuration (à fournir par l'utilisateur ou à créer) :**
        *   `wordlist.txt` : Liste des chemins/mots à tester.
        *   `extensions.txt` : Liste des extensions de fichiers à tester.
        *   `user_agents.txt` : Liste d'agents utilisateurs pour le mode furtif.
        Des exemples de ces fichiers devraient être présents dans le répertoire `DirScanner` ou créés par l'utilisateur.
*   **Utilisation :**
    ```bash
    python DirScanner/DIRScanner.py <url_cible> [options]
    ```
    Exemple :
    ```bash
    python DirScanner/DIRScanner.py http://example.com -w ma_wordlist.txt -x mes_extensions.txt --stealth
    ```
    Utilisez `python DirScanner/DIRScanner.py -h` pour voir toutes les options.
*   **Fonctionnalités Clés :**
    *   Scan multithread pour la rapidité.
    *   Mode furtif avec délais, rotation d'user-agents et respect de `robots.txt`.
    *   Détection basique du serveur web et adaptation des extensions.
    *   Sauvegarde des résultats trouvés (statut 200 OK) dans des fichiers organisés.

### 4. IPScanner (`IPScanner.py`)

*   **Description :**
    Un script wrapper autour de l'outil `nmap` pour automatiser les scans de ports réseau. Il effectue un scan rapide de tous les ports TCP (et UDP si spécifié), suivi d'un scan plus approfondi (détection de services et versions) sur les ports ouverts identifiés.
*   **Dépendances Spécifiques :**
    *   **Python :** Aucune librairie non standard.
    *   **Externes :** `nmap`.
*   **Utilisation :**
    ```bash
    python IPScanner.py <cible_ip_ou_domaine> [options]
    ```
    Exemple :
    ```bash
    python IPScanner.py 192.168.1.100 --udp -o mes_resultats_scan
    ```
    Les résultats sont sauvegardés dans un sous-répertoire horodaté (par exemple, `scans_192_168_1_100_YYYYMMDD_HHMMSS/`).
*   **Fonctionnalités Clés :**
    *   Scan TCP initial rapide sur tous les ports.
    *   Scan UDP optionnel rapide sur tous les ports.
    *   Scan approfondi (versions, scripts par défaut) sur les ports ouverts.
    *   Organisation des résultats dans des fichiers Nmap et un fichier `versions.txt` consolidé.

## Installation des Outils Externes

Assurez-vous que les outils externes suivants sont installés et configurés dans le PATH de votre système.

*   **Nmap :**
    *   Linux (Debian/Ubuntu) : `sudo apt update && sudo apt install nmap`
    *   Autres systèmes : [https://nmap.org/download.html](https://nmap.org/download.html)

*   **netexec (nxc) :**
    *   Recommandé via pipx : `pipx install netexec`
    *   Alternative via pip : `pip install netexec`
    *   Dépôt : [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

*   **rpcclient :**
    *   Fait partie de la suite Samba.
    *   Linux (Debian/Ubuntu) : `sudo apt install smbclient` (qui inclut `rpcclient`).
    *   Pour d'autres systèmes, installez les outils clients Samba.

*   **Kerbrute :**
    *   Téléchargez le binaire approprié depuis la page des releases : [https://github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases)
    *   Rendez-le exécutable (`chmod +x kerbrute_linux_amd64`) et placez-le dans un répertoire de votre PATH (ex: `/usr/local/bin`).

*   **Subfinder :**
    *   Nécessite Go installé.
    *   Commande d'installation : `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
    *   Assurez-vous que votre `GOPATH/bin` (souvent `~/go/bin`) est dans votre PATH.
    *   Dépôt : [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)

*   **Httpx :**
    *   Nécessite Go installé.
    *   Commande d'installation : `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
    *   Assurez-vous que votre `GOPATH/bin` est dans votre PATH.
    *   Dépôt : [https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)

---

Cette suite d'outils est fournie à des fins éducatives et pour des tests d'intrusion autorisés. Utilisez-les de manière responsable et éthique.
