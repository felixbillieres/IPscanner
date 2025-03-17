# IP Recon Scanner

## Description
Ce script permet d'effectuer des scans réseau automatisés à l'aide de **Nmap**. Il exécute un scan rapide pour identifier les ports ouverts, suivi d'un scan approfondi pour collecter des informations détaillées sur les services et versions en cours d'exécution.

## Fonctionnalités
- **Scan rapide TCP** : Identifie rapidement les ports ouverts.
- **Scan approfondi TCP** : Récupère les versions et services des ports ouverts.
- **Scan rapide UDP** (optionnel) : Identifie les ports UDP ouverts.
- **Scan approfondi UDP** : Récupère les informations des services UDP.
- **Sauvegarde des résultats** : Tous les résultats sont stockés dans un dossier horodaté.

## Prérequis
- **Python 3**
- **Nmap** installé et accessible depuis le terminal

## Installation
Aucune installation nécessaire, assurez-vous simplement d'avoir **Nmap** installé :
```bash
sudo apt install nmap  # Debian/Ubuntu
```

## Utilisation
Exécutez le script avec les options suivantes :
```bash
python3 scan.py <cible> [-o <répertoire_sortie>] [--udp]
```
### Arguments
- `<cible>` : Adresse IP ou domaine à scanner.
- `-o, --output` : (Optionnel) Spécifier un répertoire de sortie pour stocker les résultats.
- `--udp` : (Optionnel) Activer le scan UDP en plus du scan TCP.

### Exemples d'utilisation
- Scan TCP d'une cible :
  ```bash
  python3 scan.py 192.168.1.1
  ```
- Scan TCP + UDP d'une cible :
  ```bash
  python3 scan.py 192.168.1.1 --udp
  ```
- Scan avec un répertoire de sortie personnalisé :
  ```bash
  python3 scan.py 192.168.1.1 -o mes_scans/
  ```

## Résultats
Les résultats sont enregistrés dans un dossier nommé `oscp_scans_YYYYMMDD_HHMMSS`, contenant :
- `initial_scan_tcp.nmap` : Résultat du scan rapide TCP
- `deep_scan_tcp.nmap` : Résultat du scan détaillé TCP
- `initial_scan_udp.nmap` : (si activé) Résultat du scan rapide UDP
- `deep_scan_udp.nmap` : (si activé) Résultat du scan détaillé UDP
- `versions.txt` : Liste des versions des services détectés

## Notes
- Le scan rapide utilise une vitesse optimisée avec un nombre de retries minimal.
- L'utilisation de ce script sur des machines sans autorisation peut être illégale. Assurez-vous d'avoir les droits nécessaires avant d'exécuter un scan.

## Auteur
Script développé pour l'OSCP et les tests de pénétration.

Fait par **Elliot Belt** - GitBook : [https://felix-billieres.gitbook.io/v2](https://felix-billieres.gitbook.io/v2)
