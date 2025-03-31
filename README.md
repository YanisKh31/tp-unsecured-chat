Prénom Yanis Nom Kheffache Mail yanis.kheffache@gmail.com

#TD réalisé sur WSL #Fichiers disponibles sur la branche main
#Pour lancer certains codes, j'ai dû le faire dans un environnement virtuel car bibliothèque non dispo et non ajoutable

Mes réponses :
* Prise en main
Confidentialité des données vis-à-vis du serveur :
Les données ne sont pas du tout confidentielles car elles transitent en clair et sont accessibles au serveur. Le serveur peut lire tous les messages échangés entre les clients.


* Sérialisation pickle
Pourquoi pickle est un mauvais choix :
Pickle est dangereux car il permet la désérialisation de code arbitraire. Lors de la désérialisation, pickle peut exécuter du code Python, ce qui ouvre la porte à des attaques de type RCE (Remote Code Execution).

Alternatives à pickle :
On pourrait utiliser:
JSON (plus sécurisé mais moins performant)
MessagePack (plus performant que JSON et sécurisé)
Protocol Buffers
CBOR


* Authenticated Encryption
Pourquoi le chiffrement seul est insuffisant :
Le chiffrement seul protège la confidentialité mais pas l'intégrité. Un attaquant pourrait modifier le message chiffré sans être détecté.

Génération de salt cryptographique :
os.urandom() est la fonction recommandée pour générer un salt cryptographique en Python.

Transmission du salt :
Oui, le salt doit être transmis en clair car il n'a pas besoin d'être secret. Son rôle est juste d'empêcher les attaques par rainbow tables.


* Authenticated Encryption with Associated Data (AEAD)
Pourquoi Fernet n'est pas adapté :
Fernet ne supporte pas nativement l'AEAD qui permet d'authentifier des données supplémentaires non chiffrées. Cela permet à un serveur malveillant de modifier des métadonnées comme le nickname.
Efficacité contre le rogue server :
Avec cette solution, le rogue server ne peut plus modifier le nick ou le message sans être détecté car cela romprait l'authentification. Toute tentative de modification entraînera une erreur lors du décryptage.
