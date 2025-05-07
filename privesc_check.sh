#!/bin/bash

# privesc_check.sh - Script d'analyse approfondie des vecteurs d'escalade de privilèges Linux
# Auteur: Gemini 2.5 Pro (via l'utilisateur)
# Version: 1.0

# --- Configuration de la sortie et des couleurs ---
OUTPUT_FILE=""
WRITE_TO_FILE=0

if [ -n "$1" ]; then
    OUTPUT_FILE="$1"
    WRITE_TO_FILE=1
    # Rediriger stdout et stderr vers le fichier.
    # Les codes couleurs seront écrits tels quels dans le fichier.
    exec > "$OUTPUT_FILE" 2>&1
fi

# Définition des couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fonctions d'affichage
header() { echo -e "\n${BLUE}### $1 ###${NC}"; }
info() { echo -e "${CYAN}[*] $1${NC}"; }
warning() { echo -e "${YELLOW}[!] ATTENTION: $1${NC}"; } # Pour les éléments à examiner de près
success() { echo -e "${GREEN}[+] $1${NC}"; }
error() { echo -e "${RED}[-] ALERTE: $1${NC}"; }   # Pour les problèmes critiques

# --- Fonctions d'aide ---
check_command_exists() {
    command -v "$1" >/dev/null 2>&1
}

get_version() {
    local cmd="$1"
    if check_command_exists "$cmd"; then
        local version_output
        version_output=$("$cmd" --version 2>/dev/null || "$cmd" -v 2>/dev/null || "$cmd" -V 2>/dev/null)
        if [ -n "$version_output" ]; then
            echo "$version_output" | head -n 1
        else
            # Cas spécifiques pour certaines commandes
            if [ "$cmd" = "perl" ]; then
                perl -v 2>/dev/null | grep 'This is perl'
            elif [ "$cmd" = "nc" ]; then
                nc -h 2>&1 | grep -oE "(OpenBSD netcat|GNU netcat|Ncat version) [0-9.]*" | head -n 1 || echo "Netcat (version non standard)"
            else
                echo "Version non détectable automatiquement"
            fi
        fi
    else
        echo "Non trouvé"
    fi
}


# --- Début du script ---
main() {
    info "Début de l'analyse d'escalade de privilèges..."
    info "Date et heure: $(date)"

    # Section 1: Informations Système de Base
    header "1. Informations Système de Base"
    info "Hostname: $(hostname)"
    if check_command_exists "lsb_release"; then
        info "Distribution OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')"
    elif [ -f /etc/os-release ]; then
        info "Distribution OS: $(grep PRETTY_NAME /etc/os-release | cut -d'=' -f2 | tr -d '"')"
    elif [ -f /etc/redhat-release ]; then
        info "Distribution OS: $(cat /etc/redhat-release)"
    elif [ -f /etc/debian_version ]; then
        info "Distribution OS: Debian $(cat /etc/debian_version)"
    else
        info "Distribution OS: Impossible de déterminer"
    fi
    info "Kernel: $(uname -a)"
    info "Architecture: $(arch)"
    if check_command_exists "systemd-detect-virt"; then
        virt_status=$(systemd-detect-virt 2>/dev/null)
        info "Virtualisation (systemd-detect-virt): ${virt_status:-'non détecté ou non applicable'}"
    else
        info "Virtualisation: systemd-detect-virt non trouvé. Vérifiez manuellement (ex: dmidecode, lscpu)."
    fi

    # Section 2: Informations sur l'Utilisateur Actuel
    header "2. Informations sur l'Utilisateur Actuel"
    info "Utilisateur actuel: $(whoami)"
    info "ID Utilisateur: $(id)"
    info "UID/GID (Effectif/Réel): UID=$(id -u) (réel $(id -ru)) / GID=$(id -g) (réel $(id -rg))"
    info "Groupes: $(groups)"
    info "Contexte de sécurité (si SELinux/AppArmor): $(id -Z 2>/dev/null || echo 'Non applicable ou non trouvé')"

    # Section 3: Privilèges Sudo
    header "3. Privilèges Sudo"
    if check_command_exists "sudo"; then
        info "Version de Sudo: $(sudo -V | head -n 1)"
        info "Vérification des privilèges sudo (sudo -l):"
        sudo -l 2>/dev/null || warning "Impossible d'exécuter sudo -l. Vérifiez les droits ou si sudo est configuré."
        info "Recherche de directives sudoers potentiellement dangereuses (NOPASSWD, NOEXEC, SETENV, BYPASSNICE):"
        # Nécessite des droits de lecture sur /etc/sudoers et /etc/sudoers.d/*
        { grep -Eis 'nopasswd|noexec|setenv|bypassnice|\bALL\s*=\s*\(ALL(:ALL)?\)\s*ALL\b' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | while IFS= read -r line; do warning "Directive sudoers suspecte: $line"; done; } || info "Aucune directive suspecte trouvée ou fichiers non lisibles."
    else
        warning "La commande sudo n'est pas installée."
    fi

    # Section 4: Fichiers SUID et SGID
    header "4. Fichiers SUID et SGID"
    info "Recherche des fichiers SUID (Set User ID):"
    find / -xdev -type f -perm -4000 -ls 2>/dev/null | while IFS= read -r line; do warning "SUID: $line"; done
    info "Recherche des fichiers SGID (Set Group ID):"
    find / -xdev -type f -perm -2000 -ls 2>/dev/null | while IFS= read -r line; do warning "SGID: $line"; done
    info "Recherche de fichiers SUID/SGID dans des répertoires non standard (/opt, /usr/local, /home, /var/www):"
    find /opt /usr/local /home /var/www -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | while IFS= read -r line; do warning "SUID/SGID (non-standard): $line"; done

    # Section 5: Capacités Linux
    header "5. Capacités Linux"
    if check_command_exists "getcap"; then
        info "Recherche des fichiers avec des capacités Linux (getcap -r /):"
        getcap -r / 2>/dev/null | while IFS= read -r line; do
            warning "Capacité trouvée: $line"
            if echo "$line" | grep -qE 'cap_sys_admin|cap_setuid|cap_setgid|cap_dac_override|cap_chown|cap_net_raw|cap_net_admin'; then
                error "Capacité potentiellement dangereuse: $line"
            fi
        done
        info "Explications des capacités potentiellement dangereuses:"
        info "  cap_sys_admin: Permet de nombreuses opérations d'administration système (quasi-root)."
        info "  cap_setuid/cap_setgid: Permet de changer l'UID/GID du processus."
        info "  cap_dac_override: Permet d'outrepasser les contrôles d'accès discrétionnaires (permissions sur les fichiers)."
        info "  cap_chown: Permet de changer la propriété des fichiers."
        info "  cap_net_raw/cap_net_admin: Permet des opérations réseau de bas niveau / administration réseau."
    else
        warning "La commande getcap n'est pas installée. Impossible de vérifier les capacités Linux."
    fi

    # Section 6: Tâches Cron
    header "6. Tâches Cron"
    info "Crontab de l'utilisateur actuel ($(whoami)):"
    (crontab -l 2>/dev/null | grep -vE "^\s*#|^\s*$") || info "Aucun crontab pour l'utilisateur actuel ou crontab non accessible/vide."
    
    info "Crons système (/etc/crontab, /etc/cron.d/*, /etc/cron.hourly/*, etc.):"
    CRON_PATHS=(/etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs)
    for cron_path in "${CRON_PATHS[@]}"; do
        if [ -d "$cron_path" ]; then
            info "Vérification des fichiers dans $cron_path:"
            find "$cron_path" -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' cron_file; do
                if [ -r "$cron_file" ]; then
                    info "Contenu de $cron_file:"
                    cat "$cron_file"
                    grep -vE "^\s*#|^\s*$" "$cron_file" | while IFS= read -r line; do
                        # Tentative d'extraction de la commande (simpliste)
                        user_and_command=$(echo "$line" | sed -E 's/^\s*([0-9*\/,-]+\s+){5}//') # Enlève les 5 champs de temps
                        command_part=$(echo "$user_and_command" | awk '{if ($1 ~ /^[a-zA-Z0-9_-]+$/ && NF > 1) { $1=""; print $0; } else { print $0; }}' | sed 's/^[ \t]*//') # Enlève l'utilisateur si présent
                        script_path=$(echo "$command_part" | awk '{print $1}')

                        if [[ -n "$script_path" && "$script_path" != "MAILTO=" && "$script_path" != "SHELL=" && "$script_path" != "PATH=" && "$script_path" != "HOME=" ]]; then
                            if [[ "$script_path" != /* && "$script_path" != "~/"* ]]; then
                                warning "Cron ($cron_file) utilise un chemin potentiellement relatif: $command_part"
                            fi
                            # Vérifier si le script/binaire est inscriptible
                            resolved_script_path=$(realpath "$script_path" 2>/dev/null || echo "$script_path")
                            if [ -f "$resolved_script_path" ]; then
                                if [ -w "$resolved_script_path" ]; then
                                    error "Script/binaire '$resolved_script_path' appelé par cron ($cron_file) est INCRIPTIBLE !"
                                fi
                                if [ -O "$resolved_script_path" ]; then
                                    error "Script/binaire '$resolved_script_path' appelé par cron ($cron_file) APPARTIENT à l'utilisateur actuel !"
                                fi
                            elif [ -d "$resolved_script_path" ]; then
                                warning "Chemin '$resolved_script_path' appelé par cron ($cron_file) est un répertoire."
                            fi
                        fi
                    done
                else
                    warning "Fichier cron $cron_file non lisible."
                fi
            done
        elif [ -f "$cron_path" ]; then
             if [ -r "$cron_path" ]; then
                info "Contenu de $cron_path:"
                cat "$cron_path" # Similaire à ci-dessus pour /etc/crontab
             else
                warning "Fichier cron $cron_path non lisible."
             fi
        fi
    done

    info "Vérification des fichiers/répertoires cron inscriptibles dans les emplacements standards :"
    find /etc/cron* /var/spool/cron -xdev \( -type f -o -type d \) -writable -ls 2>/dev/null | while IFS= read -r line; do error "Élément cron inscriptible: $line"; done
    
    info "Recherche de fichiers cron exécutables par l'utilisateur actuel dans des emplacements non standard (ex: répertoires personnels):"
    find "$HOME" -type f -iname "*cron*" -user "$(whoami)" -perm /u+x -print 2>/dev/null | while read -r f; do warning "Fichier potentiellement lié à cron, exécutable et appartenant à l'utilisateur: $f (vérifier s'il est appelé par une tâche cron)"; done


    # Section 7: Variables d'Environnement
    header "7. Variables d'Environnement"
    info "Variables d'environnement actuelles (env):"
    env | sort
    if [ -n "$LD_PRELOAD" ]; then
        error "LD_PRELOAD est défini: $LD_PRELOAD"
    else
        info "LD_PRELOAD n'est pas défini."
    fi
    if [ -n "$LD_LIBRARY_PATH" ]; then
        warning "LD_LIBRARY_PATH est défini: $LD_LIBRARY_PATH"
    else
        info "LD_LIBRARY_PATH n'est pas défini."
    fi
    info "PATH: $PATH" # Analysé plus en détail dans la section 16

    # Section 8: Services et Sockets Réseau
    header "8. Services et Sockets Réseau en Écoute"
    if check_command_exists "ss"; then
        info "Sockets en écoute (ss -tulnp):"
        ss -tulnp
    elif check_command_exists "netstat"; then
        info "Sockets en écoute (netstat -tulnp):"
        netstat -tulnp
    else
        warning "Ni ss ni netstat ne sont installés. Impossible de lister les sockets."
    fi
    info "Vérifiez les services écoutant sur des interfaces spécifiques (pas seulement 0.0.0.0 ou ::) et les services non standards."

    # Section 9: Informations sur les Utilisateurs et les Groupes
    header "9. Informations sur les Utilisateurs et les Groupes"
    info "Contenu de /etc/passwd (extrait):"
    awk -F: '{print "Utilisateur: " $1 ", UID: " $3 ", GID: " $4 ", Home: " $6 ", Shell: " $7}' /etc/passwd
    info "Utilisateurs avec UID 0 (potentiels doublons de root):"
    awk -F: '($3 == 0) {print $1}' /etc/passwd | while IFS= read -r user; do if [ "$user" != "root" ]; then error "Utilisateur avec UID 0: $user"; else info "Utilisateur root (UID 0): $user"; fi; done
    
    info "Contenu de /etc/group (extrait):"
    awk -F: '{print "Groupe: " $1 ", GID: " $3 ", Membres: " $4}' /etc/group

    info "Vérification de la lisibilité de /etc/shadow:"
    if [ -r "/etc/shadow" ]; then
        warning "/etc/shadow est lisible par l'utilisateur actuel !"
        info "Groupes sans mot de passe (champ '!' ou vide dans /etc/gshadow - nécessite la lecture de gshadow):"
        if [ -r "/etc/gshadow" ]; then
            awk -F: '($2 == "!" || $2 == "") { print $1 }' /etc/gshadow | while IFS= read -r group_name; do warning "Groupe sans mot de passe (dans gshadow): $group_name"; done
        else
            warning "/etc/gshadow n'est pas lisible."
        fi
    else
        info "/etc/shadow n'est pas lisible par l'utilisateur actuel (ce qui est normal)."
    fi


    # Section 10: Partages de Fichiers Montés
    header "10. Partages de Fichiers Montés"
    info "Systèmes de fichiers montés (df -h):"
    df -h
    info "Points de montage et options (mount):"
    mount
    info "Vérification des options de montage (nosuid, noexec):"
    mount | awk '$0 !~ /nosuid/ && ($3 ~ /\/home|\/tmp|\/var\/tmp|\/mnt|\/media|^\/run\/media/) {print "Montage SANS nosuid sur partition sensible: " $0}' | while IFS= read -r line; do warning "$line"; done
    mount | awk '$0 !~ /noexec/ && ($3 ~ /\/home|\/tmp|\/var\/tmp|\/mnt|\/media|^\/run\/media/) {print "Montage SANS noexec sur partition sensible: " $0}' | while IFS= read -r line; do warning "$line"; done

    # Section 11: Logiciels Installés et Versions
    header "11. Logiciels Installés et Versions"
    info "Versions de logiciels courants (si trouvés):"
    for pkg_mgr in dpkg rpm; do if check_command_exists $pkg_mgr; then PKG_MANAGER=$pkg_mgr; break; fi; done
    if [ "$PKG_MANAGER" = "dpkg" ]; then
        info "Gestionnaire de paquets: dpkg (Debian/Ubuntu)"
        # dpkg -l | head -n 20 # Trop verbeux pour une sortie console directe
    elif [ "$PKG_MANAGER" = "rpm" ]; then
        info "Gestionnaire de paquets: rpm (RedHat/CentOS/Fedora)"
        # rpm -qa | head -n 20 # Trop verbeux
    else
        info "Gestionnaire de paquets non détecté (dpkg/rpm)."
    fi
    
    COMMON_TOOLS=("gcc" "python" "python3" "perl" "nc" "netcat" "ncat" "wget" "curl" "git" "vim" "nano" "screen" "tmux")
    for tool in "${COMMON_TOOLS[@]}"; do
        version=$(get_version "$tool")
        info "Version de $tool: $version"
    done
    warning "Il est crucial de vérifier manuellement les versions des logiciels installés (en particulier les services réseau, les outils SUID et les bibliothèques) contre les bases de données de vulnérabilités (par exemple, CVE Details, NVD)."
    if [ "$PKG_MANAGER" = "dpkg" ]; then
        info "Sur les systèmes Debian/Ubuntu, vous pouvez chercher des paquets liés à des vulnérabilités avec: dpkg -l | grep -Ei 'vuln|security|advisory'"
    fi


    # Section 12: Fichiers de Configuration Intéressants
    header "12. Fichiers de Configuration Intéressants"
    info "Recherche de mots-clés sensibles (password, secret, token, api_key, etc.) dans les fichiers de configuration."
    info "Les fichiers listés ci-dessous doivent être examinés manuellement pour des informations d'identification."
    SEARCH_PATHS=("/etc/" "/opt/" "/usr/local/etc/" "/var/www/" "$HOME/.config/" "$HOME/")
    KEYWORDS_REGEX='password\b|passwd\b|pwd\b|secret\b|token\b|api_key\b|apikey\b|auth_key\b|private_key\b|credentials'
    for search_path in "${SEARCH_PATHS[@]}"; do
        if [ -d "$search_path" ]; then
            info "Recherche dans $search_path ..."
            # Utiliser find pour éviter les problèmes avec les noms de fichiers contenant des espaces et pour mieux contrôler la profondeur
            find "$search_path" -xdev -type f -print0 2>/dev/null | while IFS= read -r -d $'\0' file; do
                if LC_ALL=C grep -qisE "$KEYWORDS_REGEX" "$file"; then
                    warning "Fichier potentiellement sensible à examiner: $file"
                fi
            done
        fi
    done
    # Fichiers spécifiques
    find "$HOME" -xdev -type f \( -name ".*hist*" -o -name ".*rc" -o -name ".*profile" -o -name "*.kdbx" -o -name "*.psafe3" \) -print0 2>/dev/null | while IFS= read -r -d $'\0' file; do
         if LC_ALL=C grep -qisE "$KEYWORDS_REGEX" "$file"; then
            warning "Fichier personnel potentiellement sensible à examiner: $file"
        fi
    done

    info "Vérification des permissions sur les fichiers de configuration dans /opt/ et /usr/local/ (et sous-répertoires config/etc):"
    find /opt /usr/local \( -path "*/etc/*" -o -path "*/config/*" -o -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.xml" -o -name "*.yml" -o -name "*.yaml" \) -type f -ls 2>/dev/null | while IFS= read -r line; do
        perms=$(echo "$line" | awk '{print $3}')
        file_path=$(echo "$line" | awk '{print $NF}')
        # Vérifier si inscriptible par 'others' ou 'group' (si l'utilisateur n'est pas le propriétaire et n'est pas dans le groupe propriétaire)
        if [[ "${perms:7:1}" == "w" || ( "${perms:4:1}" == "w" && $(stat -c %U "$file_path" 2>/dev/null) != "$(whoami)" && $(stat -c %G "$file_path" 2>/dev/null) != "$(id -gn)" ) ]]; then
            warning "Fichier de configuration avec permissions potentiellement larges: $line"
        fi
    done

    # Section 13: Analyse de Répertoires Temporaires
    header "13. Analyse de Répertoires Temporaires"
    TEMP_DIRS=("/tmp" "/var/tmp" "/dev/shm")
    for temp_dir in "${TEMP_DIRS[@]}"; do
        if [ -d "$temp_dir" ]; then
            info "Permissions et bit sticky pour $temp_dir:"
            ls -ld "$temp_dir"
            perms=$(stat -c "%A" "$temp_dir" 2>/dev/null)
            if [[ "$perms" != *"t"* && "$perms" == *"w"* ]]; then # Si inscriptible par 'others' et pas de sticky bit
                 warning "Le bit sticky est manquant sur $temp_dir et il est inscriptible par 'others' !"
            elif [[ "$perms" != *"t"* ]]; then
                 warning "Le bit sticky est manquant sur $temp_dir."
            fi
        else
            info "Répertoire temporaire $temp_dir non trouvé."
        fi
    done

    # Section 14: Journaux et Historique des Commandes
    header "14. Journaux et Historique des Commandes"
    HISTFILE_PATH="${HISTFILE:-$HOME/.bash_history}"
    info "Historique des commandes de l'utilisateur actuel (dernier 50, si disponible):"
    if [ -f "$HISTFILE_PATH" ] && [ -r "$HISTFILE_PATH" ]; then
        tail -n 50 "$HISTFILE_PATH"
        if LC_ALL=C grep -Eis "$KEYWORDS_REGEX" "$HISTFILE_PATH"; then
            warning "Mots-clés sensibles trouvés dans l'historique des commandes ($HISTFILE_PATH) !"
        fi
    else
        info "Fichier d'historique ($HISTFILE_PATH) non trouvé ou non lisible."
    fi
    # Autres fichiers d'historique courants
    OTHER_HIST_FILES=("$HOME/.zsh_history" "$HOME/.sh_history" "$HOME/.history" "$HOME/.ash_history" "$HOME/.mysql_history" "$HOME/.psql_history")
    for hist_f in "${OTHER_HIST_FILES[@]}"; do
        if [ -f "$hist_f" ] && [ -r "$hist_f" ]; then
            info "Vérification de $hist_f..."
            if LC_ALL=C grep -Eis "$KEYWORDS_REGEX" "$hist_f"; then
                warning "Mots-clés sensibles trouvés dans $hist_f !"
            fi
        fi
    done

    info "Tentative de lecture des fichiers d'historique d'autres utilisateurs (si permissions le permettent):"
    find /home -maxdepth 2 -name ".*hist*" -type f 2>/dev/null | while read -r other_hist_file; do
        if [ -r "$other_hist_file" ] && [ "$(stat -c %U "$other_hist_file" 2>/dev/null)" != "$(whoami)" ]; then
            warning "Historique d'un autre utilisateur potentiellement lisible: $other_hist_file"
        fi
    done

    info "Vérification des permissions sur les fichiers journaux (/var/log):"
    find /var/log -xdev -type f \( -writable -o -perm /g+w \) -ls 2>/dev/null | while IFS= read -r line; do
        warning "Fichier journal avec permissions d'écriture larges: $line"
    done

    # Section 15: Processus en Cours d'Exécution
    header "15. Processus en Cours d'Exécution"
    info "Liste de tous les processus (ps auxf):"
    ps auxf
    info "Recherche de processus exécutés par root avec des chemins non absolus:"
    ps aux | awk '$1 == "root" && $2 != '"$$"' && $11 !~ /^\// && $11 !~ /^\[.*\]$/ {print $0}' | while IFS= read -r line; do warning "Processus root avec chemin non absolu: $line"; done
    info "Recherche de processus 'orphelins' (PPID=1) exécutés par des utilisateurs non root:"
    ps -eo user,pid,ppid,comm,args --forest | awk '$1 != "root" && $1 != "USER" && $3 == 1 {print $0}' | while IFS= read -r line; do warning "Processus orphelin non-root: $line"; done
    # Arguments suspects est subjectif, l'utilisateur doit vérifier `ps auxf`

    # Section 16: Chemins Inclus dans $PATH (Analyse de Sécurité)
    header "16. Analyse de Sécurité du PATH"
    info "Variable PATH: $PATH"
    IFS_ORIG="$IFS"
    IFS=:
    for path_dir in $PATH; do
        info "Analyse du répertoire PATH: $path_dir"
        if [ -z "$path_dir" ]; then # Cas de :: ou : à la fin/début
            path_dir="." # Répertoire courant
            warning "Répertoire courant (.) implicitement dans le PATH."
        fi
        if [ -d "$path_dir" ]; then
            if [ -w "$path_dir" ]; then
                error "Répertoire INCRIPTIBLE dans le PATH: $path_dir (ls -ld $path_dir)"
                ls -ld "$path_dir"
            else
                info "Répertoire dans le PATH (non inscriptible par l'utilisateur actuel): $path_dir"
            fi
            # Vérifier si possédé par root mais inscriptible par groupe/autres
            owner=$(stat -c '%U' "$path_dir" 2>/dev/null)
            perms_str=$(stat -c '%A' "$path_dir" 2>/dev/null)
            # Si possédé par root et inscriptible par groupe (et l'utilisateur n'est pas root) ou inscriptible par 'others'
            if [ "$owner" == "root" ] && [ "$(id -u)" != "0" ]; then
                if [[ "${perms_str:5:1}" == "w" || "${perms_str:8:1}" == "w" ]]; then
                     warning "Répertoire '$path_dir' dans le PATH est possédé par root mais inscriptible par le groupe ou 'others'."
                     ls -ld "$path_dir"
                fi
            fi
        else
            warning "Répertoire non existant dans le PATH: $path_dir"
        fi
    done
    IFS="$IFS_ORIG"

    # Section 17: Scripts ou Binaires Personnels dans le $PATH
    header "17. Scripts ou Binaires Personnels dans le PATH"
    info "Recherche de scripts/binaires appartenant à l'utilisateur actuel dans les répertoires du PATH:"
    IFS_ORIG="$IFS"
    IFS=:
    for path_dir in $PATH; do
        if [ -z "$path_dir" ]; then path_dir="."; fi # Gérer les chemins vides comme répertoire courant
        if [ -d "$path_dir" ]; then
            find "$path_dir" -maxdepth 1 -type f -user "$(whoami)" -executable -print 2>/dev/null | while read -r user_script; do
                warning "Script/Binaire personnel dans le PATH: $user_script"
            done
        fi
    done
    IFS="$IFS_ORIG"

    # Section 18: Fichiers Récemment Modifiés
    header "18. Fichiers Récemment Modifiés (dernière heure)"
    info "Fichiers appartenant à root récemment modifiés (hors /proc, /sys, /dev):"
    find / -xdev -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -owner root -mmin -60 -type f -ls 2>/dev/null | while IFS= read -r line; do warning "Fichier root modifié < 60min: $line"; done
    info "Fichiers SUID/SGID récemment modifiés (hors /proc, /sys, /dev):"
    find / -xdev -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \( -perm -4000 -o -perm -2000 \) -mmin -60 -type f -ls 2>/dev/null | while IFS= read -r line; do error "Fichier SUID/SGID modifié < 60min: $line"; done

    # Section 19: Vérification des Backups
    header "19. Vérification des Fichiers de Sauvegarde Potentiels"
    info "Recherche de fichiers de sauvegarde potentiels (*.bak, *.old, etc.):"
    find / -xdev -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -type f -regextype posix-extended -regex ".*\.(bak|backup|old|save|swp|swo|~|bk|copy|orig)$" -ls 2>/dev/null | while IFS= read -r line; do warning "Fichier de backup potentiel: $line"; done

    # Section 20: Cloud Environment Checks
    header "20. Vérification de l'Environnement Cloud (Métadonnées)"
    if check_command_exists "curl"; then
        CURL_CMD="curl -s --connect-timeout 2"
    elif check_command_exists "wget"; then
        CURL_CMD="wget -qO- --timeout=2" # wget écrit sur stdout avec -qO-
    else
        CURL_CMD=""
        info "curl ou wget non trouvés. Impossible de vérifier les métadonnées cloud."
    fi

    if [ -n "$CURL_CMD" ]; then
        info "Tentative de récupération des métadonnées AWS..."
        aws_metadata=$($CURL_CMD http://169.254.169.254/latest/meta-data/ 2>/dev/null)
        if [ -n "$aws_metadata" ]; then
            warning "Métadonnées AWS détectées! Examiner attentivement:"
            echo "$aws_metadata" | head -n 10 # Afficher un extrait
            # Pourrait être étendu pour récupérer des infos spécifiques comme les rôles IAM
            iam_role=$($CURL_CMD http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)
            if [ -n "$iam_role" ]; then
                error "Rôle IAM potentiellement exposé via métadonnées AWS: $iam_role"
            fi
        else
            info "Aucune métadonnée AWS détectée ou service non accessible."
        fi

        info "Tentative de récupération des métadonnées Azure..."
        # L'option -H Metadata:true est pour Azure IMDS
        if [[ "$CURL_CMD" == "curl"* ]]; then
            azure_metadata=$($CURL_CMD -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)
        else # wget
            azure_metadata=$(wget -qO- --header="Metadata:true" --timeout=2 "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)
        fi
        if [ -n "$azure_metadata" ] && [[ "$azure_metadata" != *"error"* ]] && [[ "$azure_metadata" == *"vmId"* ]]; then # Vérifier si c'est bien du JSON Azure
            warning "Métadonnées Azure détectées! Examiner attentivement:"
            echo "$azure_metadata" | head -n 10 # Afficher un extrait
        else
            info "Aucune métadonnée Azure détectée ou service non accessible."
        fi

        info "Tentative de récupération des métadonnées GCP..."
        # L'option -H "Metadata-Flavor: Google" est pour GCP
         if [[ "$CURL_CMD" == "curl"* ]]; then
            gcp_metadata=$($CURL_CMD -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/?recursive=true 2>/dev/null)
        else # wget
            gcp_metadata=$(wget -qO- --header="Metadata-Flavor: Google" --timeout=2 http://metadata.google.internal/computeMetadata/v1/?recursive=true 2>/dev/null)
        fi

        if [ -n "$gcp_metadata" ] && [[ "$gcp_metadata" != *"</html>"* ]] && [[ "$gcp_metadata" == *"instance/"* ]]; then # Vérifier si c'est bien du JSON/texte GCP
            warning "Métadonnées GCP détectées! Examiner attentivement:"
            echo "$gcp_metadata" | head -n 10 # Afficher un extrait
        else
            info "Aucune métadonnée GCP détectée ou service non accessible."
        fi
    fi

    # --- Fin du script ---
    if [ "$WRITE_TO_FILE" -eq 1 ]; then
        echo -e "\n${GREEN}=======================================================================${NC}"
        echo -e "${GREEN} Vérification terminée.                                                  ${NC}"
        echo -e "${GREEN} La sortie complète a été enregistrée dans ${CYAN}$OUTPUT_FILE${NC}${GREEN}.${NC}"
        echo -e "${GREEN} Veuillez examiner attentivement ce fichier, en particulier les sections ${NC}"
        echo -e "${GREEN} marquées avec ${RED}ALERTE${NC} et ${YELLOW}ATTENTION${NC}.${NC}"
        echo -e "${GREEN}=======================================================================${NC}"
    else
        # Ce message s'affichera sur la console si pas de redirection
        echo -e "\n${GREEN}=======================================================================${NC}"
        echo -e "${GREEN} Vérification terminée.                                                  ${NC}"
        echo -e "${GREEN} Veuillez examiner attentivement la sortie ci-dessus, en particulier    ${NC}"
        echo -e "${GREEN} les sections marquées avec ${RED}ALERTE${NC} et ${YELLOW}ATTENTION${NC}.${NC}"
        echo -e "${GREEN}=======================================================================${NC}"
    fi
}

# Exécuter la fonction principale
main

exit 0 