"""
Script semplice per testare login Sorare
Verifica se le credenziali funzionano e stampa il risultato
"""

import requests
import bcrypt
import os
import sys
from dotenv import load_dotenv

def get_user_salt(email):
    """Ottiene il salt per l'hash della password"""
    try:
        response = requests.get(f"https://api.sorare.com/api/v1/users/{email}")
        if response.status_code == 200:
            return response.json()["salt"]
        else:
            return None
    except Exception as e:
        print(f"Errore nell'ottenimento del salt: {e}")
        return None

def hash_password(password, salt):
    """Crea hash della password con bcrypt"""
    return bcrypt.hashpw(password.encode(), salt.encode()).decode()

def test_sorare_login(email, password):
    """Testa il login su Sorare"""
    print("🔐 Testando login Sorare...")
    
    # Ottieni salt
    print("📡 Ottenendo salt utente...")
    salt = get_user_salt(email)
    if not salt:
        print("❌ Impossibile ottenere salt. Email non valida?")
        return False
    
    # Hash password
    print("🔒 Crittografando password...")
    hashed_password = hash_password(password, salt)
    
    # Prepara la mutation per il login
    mutation = """
    mutation SignInMutation($input: signInInput!) {
        signIn(input: $input) {
            currentUser {
                slug
                nickname
                email
            }
            errors {
                message
                path
            }
        }
    }
    """
    
    variables = {
        "input": {
            "email": email,
            "password": hashed_password
        }
    }
    
    # Effettua la chiamata GraphQL
    print("🌐 Tentativo di login...")
    try:
        response = requests.post(
            "https://api.sorare.com/graphql",
            json={"query": mutation, "variables": variables},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code != 200:
            print(f"❌ Errore HTTP: {response.status_code}")
            return False
        
        data = response.json()
        
        # Controlla se ci sono errori
        if "errors" in data:
            print(f"❌ Errore GraphQL: {data['errors']}")
            return False
        
        sign_in_data = data.get("data", {}).get("signIn", {})
        
        if sign_in_data.get("errors"):
            print(f"❌ Errore login: {sign_in_data['errors'][0]['message']}")
            return False
        
        current_user = sign_in_data.get("currentUser")
        if current_user:
            print(f"✅ LOGIN RIUSCITO!")
            print(f"👤 Utente: {current_user['nickname']}")
            print(f"📧 Email: {current_user['email']}")
            print(f"🔗 Slug: {current_user['slug']}")
            return True
        else:
            print("❌ Login fallito - risposta vuota")
            return False
            
    except Exception as e:
        print(f"❌ Errore durante il login: {e}")
        return False

def main():
    """Funzione principale"""
    print("🎮 SORARE LOGIN TEST")
    print("=" * 40)
    
    # Carica variabili d'ambiente
    load_dotenv()
    
    # Ottieni credenziali
    email = os.getenv("SORARE_EMAIL")
    password = os.getenv("SORARE_PASSWORD")
    
    if not email or not password:
        print("❌ Credenziali mancanti!")
        print("💡 Assicurati di avere SORARE_EMAIL e SORARE_PASSWORD nel file .env")
        print("   oppure come variabili d'ambiente")
        sys.exit(1)
    
    # Testa login
    success = test_sorare_login(email, password)
    
    if success:
        print("\n🎉 SEI LOGGATO SU SORARE!")
        sys.exit(0)
    else:
        print("\n😞 NON SEI LOGGATO SU SORARE")
        sys.exit(1)

if __name__ == "__main__":
    main()