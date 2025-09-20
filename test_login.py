"""
Script semplice per testare login Sorare - Versione migliorata
Gestisce meglio gli errori di geolocalizzazione
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
        return False, "INVALID_EMAIL"
    
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
            return False, "HTTP_ERROR"
        
        data = response.json()
        
        # Controlla se ci sono errori
        if "errors" in data:
            print(f"❌ Errore GraphQL: {data['errors']}")
            return False, "GRAPHQL_ERROR"
        
        sign_in_data = data.get("data", {}).get("signIn", {})
        
        if sign_in_data.get("errors"):
            error_message = sign_in_data['errors'][0]['message']
            print(f"❌ Errore login: {error_message}")
            
            # Gestisci errori specifici
            if "authenticate_from_new_country" in error_message:
                print("🌍 ERRORE GEOLOCALIZZAZIONE RILEVATO!")
                print("📧 Controlla la tua email per autorizzare la nuova location")
                print("🔗 Oppure fai login manuale su sorare.com per confermare")
                return False, "NEW_LOCATION"
            elif "wrong" in error_message.lower():
                print("🔑 Credenziali errate - controlla email e password")
                return False, "WRONG_CREDENTIALS" 
            else:
                return False, "OTHER_ERROR"
        
        current_user = sign_in_data.get("currentUser")
        if current_user:
            print(f"✅ LOGIN RIUSCITO!")
            print(f"👤 Utente: {current_user['nickname']}")
            print(f"📧 Email: {current_user['email']}")
            print(f"🔗 Slug: {current_user['slug']}")
            return True, "SUCCESS"
        else:
            print("❌ Login fallito - risposta vuota")
            return False, "EMPTY_RESPONSE"
            
    except Exception as e:
        print(f"❌ Errore durante il login: {e}")
        return False, "NETWORK_ERROR"

def main():
    """Funzione principale"""
    print("🎮 SORARE LOGIN TEST - v2.0")
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
    success, error_code = test_sorare_login(email, password)
    
    print("\n" + "=" * 40)
    
    if success:
        print("🎉 SEI LOGGATO SU SORARE!")
        print("✅ Il tuo script funziona perfettamente!")
        print("🚀 Pronto per aggiungere automazione!")
        sys.exit(0)
    else:
        print("😞 NON SEI LOGGATO SU SORARE")
        
        # Messaggi specifici per ogni errore
        if error_code == "NEW_LOCATION":
            print("\n💡 SOLUZIONE:")
            print("1. Controlla email da Sorare per autorizzare nuova location")
            print("2. OPPURE fai login manuale su sorare.com")
            print("3. Poi ri-esegui questo script")
            print("\n⚠️  NOTA: Le tue credenziali sono corrette!")
        elif error_code == "WRONG_CREDENTIALS":
            print("\n💡 SOLUZIONE:")
            print("1. Verifica email e password su sorare.com")
            print("2. Aggiorna le credenziali in .env o GitHub Secrets")
        elif error_code == "INVALID_EMAIL":
            print("\n💡 SOLUZIONE:")
            print("1. Controlla che l'email sia scritta correttamente")
            print("2. Assicurati sia la stessa usata per registrarti su Sorare")
        
        sys.exit(1)

if __name__ == "__main__":
    main()
