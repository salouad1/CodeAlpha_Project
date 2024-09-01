import os
import sqlite3
import hashlib

# Vulnérabilité 1 : Chemin de fichier non sécurisé
def create_file_with_content(filename, content):
    # Vulnérabilité 2 : Pas de validation de l'entrée
    # Les utilisateurs peuvent spécifier des chemins arbitraires
    with open(filename, 'w') as file:
        file.write(content)

def read_file(filename):
    # Vulnérabilité 3 : Lecture de fichier sans validation
    # Lecture de fichiers sans restrictions, y compris ceux en dehors de l'application
    with open(filename, 'r') as file:
        return file.read()

def hash_data(data):
    # Vulnérabilité 4 : Utilisation d'un algorithme de hachage faible (SHA-1)
    # SHA-1 est considéré comme peu sécurisé
    hashed = hashlib.sha1(data.encode('utf-8')).hexdigest()
    return hashed

def store_data_in_db(data):
    # Vulnérabilité 5 : Injection SQL
    # Utilisation de paramètres non sécurisés dans la requête SQL
    conn = sqlite3.connect(':memory:')  # Utilisation d'une base de données en mémoire
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE data (info TEXT)")
    cursor.execute(f"INSERT INTO data (info) VALUES ('{data}')")  # Vulnérabilité d'injection SQL
    conn.commit()
    conn.close()

def main():
    # Vulnérabilité 6 : Pas de gestion des erreurs pour les opérations de fichier
    try:
        filename = input("Entrez le nom du fichier à créer: ")
        content = input("Entrez le contenu du fichier: ")
        create_file_with_content(filename, content)
        print("Fichier créé avec succès.")
    except Exception as e:
        print(f"Erreur lors de la création du fichier: {e}")

    try:
        filename = input("Entrez le nom du fichier à lire: ")
        content = read_file(filename)
        print(f"Contenu du fichier:\n{content}")
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier: {e}")

    try:
        data = input("Entrez les données à stocker dans la base de données: ")
        hashed_data = hash_data(data)  # Hachage des données avant stockage
        store_data_in_db(hashed_data)
        print("Données stockées avec succès.")
    except Exception as e:
        print(f"Erreur lors du stockage des données: {e}")

if __name__ == "__main__":
    main()
