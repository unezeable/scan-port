# Network Scanner

## Description  
Ce script est un scanner réseau basé sur ICMP qui permet d'identifier les hôtes actifs sur un sous-réseau donné.  
Il envoie des paquets UDP aux adresses IP du réseau pour provoquer des réponses ICMP et détecter les hôtes en ligne.  

🚀 **Inspiré du livre** *Black Hat Python*  

## Fonctionnalités  
- Envoi de paquets UDP sur un sous-réseau spécifié  
- Capture et analyse des réponses ICMP  
- Affichage des hôtes actifs  

## Utilisation  

# Cloner le dépôt
   git clone https://github.com/unezeable/scan-port.git
   cd network-scanner

# Exécuter le script
   python scanner.py [votre_ip_locale]
   
# Si aucune adresse IP n'est précisée, `192.168.1.24` sera utilisée par défaut.

# Prérequis
   - Python 3
   - Droits administrateur (requis pour la capture de paquets bruts)

# Avertissement ⚠
   Ce script est destiné à des fins éducatives et de tests de sécurité sur des réseaux dont vous avez l'autorisation. 
   L'utilisation sur un réseau tiers sans permission peut être illégale.
