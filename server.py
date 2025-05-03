import asyncio
import websockets
import json
import datetime
import logging
import argparse
import getpass
import bcrypt
import os
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%d-%m-%Y %H:%M:%S')

# --- Globalne Struktury Danych (Uproszczenie - brak szyfrowania plików) ---
# W pełnym rozwiązaniu: ładowane/zapisywane z/do zaszyfrowanych plików JSON
USERS = {}  # { "username": {"password_hash": b"...", "registration_date": "...", "last_online": "...", "account_status": ["active"], "websocket": None, "session_key": None }}
MESSAGES = []  # [{"id": 1, "timestamp": "...", "author": "...", "text": "...", "flags": []}]
MESSAGE_COUNTER = 0
CLIENTS = {}  # { websocket: {"username": None, "session_key": None} }
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY_PEM = None

# --- Blokady dla dostępu do współdzielonych zasobów ---
# Konieczne, bo CLI działa w innym wątku niż główna pętla asyncio
users_lock = threading.Lock()
messages_lock = threading.Lock()
clients_lock = threading.Lock()


# --- Funkcje Kryptograficzne ---

def load_server_keys(private_key_path, password):
    global SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY_PEM
    try:
        with open(private_key_path, "rb") as key_file:
            SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode('utf-8'),
                backend=default_backend()
            )
        public_key = SERVER_PRIVATE_KEY.public_key()
        SERVER_PUBLIC_KEY_PEM = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logging.info("Pomyślnie załadowano klucze serwera.")
        return True
    except (ValueError, TypeError, FileNotFoundError) as e:
        logging.error(f"Błąd ładowania klucza prywatnego: {e}. Sprawdź hasło lub ścieżkę.")
        return False
    except Exception as e:
        logging.error(f"Nieoczekiwany błąd podczas ładowania kluczy: {e}")
        return False


def decrypt_session_key(encrypted_key_b64):
    try:
        encrypted_key = base64.b64decode(encrypted_key_b64)
        session_key = SERVER_PRIVATE_KEY.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return session_key
    except Exception as e:
        logging.error(f"Błąd deszyfrowania klucza sesji: {e}")
        return None


def encrypt_message_aes(session_key, plaintext):
    try:
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)  # AES-GCM wymaga nonce
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        # Zwracamy nonce i ciphertext razem, np. jako base64
        return base64.b64encode(nonce + ciphertext).decode('utf-8')
    except Exception as e:
        logging.error(f"Błąd szyfrowania AES: {e}")
        return None


def decrypt_message_aes(session_key, encrypted_data_b64):
    try:
        encrypted_data = base64.b64decode(encrypted_data_b64)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:  # Np. InvalidTag jeśli integralność naruszona
        logging.error(f"Błąd deszyfrowania AES lub weryfikacji: {e}")
        return None


# --- Funkcje Pomocnicze ---

def get_current_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


async def send_encrypted(websocket, session_key, message_type, payload):
    """Szyfruje i wysyła wiadomość w formacie JSON"""
    try:
        message_json = json.dumps({"type": message_type, "payload": payload})
        encrypted_payload = encrypt_message_aes(session_key, message_json)
        if encrypted_payload:
            await websocket.send(json.dumps({"type": "encrypted_message", "data": encrypted_payload}))
        else:
            logging.warning(f"Nie udało się zaszyfrować wiadomości dla {websocket.remote_address}")
    except websockets.exceptions.ConnectionClosed:
        logging.info(f"Połączenie zamknięte podczas wysyłania do {websocket.remote_address}")
    except Exception as e:
        logging.error(f"Błąd wysyłania do {websocket.remote_address}: {e}")


async def broadcast(message_type, payload, exclude_websocket=None):
    """Rozsyła wiadomość do wszystkich zalogowanych klientów"""
    with clients_lock:
        tasks = []
        for ws, client_info in CLIENTS.items():
            if ws != exclude_websocket and client_info.get("username") and client_info.get("session_key"):
                # Tworzymy zadanie asyncio dla każdego wysłania
                tasks.append(
                    asyncio.create_task(send_encrypted(ws, client_info["session_key"], message_type, payload))
                )
        if tasks:
            await asyncio.gather(*tasks)  # Czekamy na zakończenie wszystkich zadań wysyłania


# --- Obsługa Logiki Serwera ---

async def handle_login(websocket, client_info, username, password):
    with users_lock:
        user_data = USERS.get(username)
        now = get_current_timestamp()

        if user_data:  # Istniejący użytkownik
            if "banned" in user_data["account_status"]:
                await send_encrypted(websocket, client_info["session_key"], "login_status",
                                     {"success": False, "message": "Konto zbanowane."})
                await websocket.close(reason="Banned")
                return False

            if bcrypt.checkpw(password.encode('utf-8'), user_data["password_hash"]):
                user_data["last_online"] = now
                user_data["websocket"] = websocket  # Powiąż websocket z użytkownikiem
                client_info["username"] = username
                USERS[username] = user_data  # Aktualizuj dane w głównym słowniku
                logging.info(f"{now} [Polaczenie klienta] Nazwa klienta: {username}")
                await send_encrypted(websocket, client_info["session_key"], "login_status",
                                     {"success": True, "message": f"Zalogowano jako {username}."})
                # Poinformuj innych o nowym użytkowniku
                await broadcast("user_status_update", {"username": username, "status": "online"},
                                exclude_websocket=websocket)
                return True
            else:
                await send_encrypted(websocket, client_info["session_key"], "login_status",
                                     {"success": False, "message": "Nieprawidłowa nazwa użytkownika lub hasło."})
                return False
        else:  # Nowy użytkownik - rejestracja
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            USERS[username] = {
                "password_hash": hashed_password,
                "registration_date": now,
                "last_online": now,
                "account_status": ["active"],
                "websocket": websocket,
                "session_key": client_info["session_key"]  # Już mamy klucz sesji
            }
            client_info["username"] = username
            logging.info(f"{now} [Rejestracja klienta] Nazwa klienta: {username}")
            await send_encrypted(websocket, client_info["session_key"], "login_status",
                                 {"success": True, "message": f"Zarejestrowano i zalogowano jako {username}."})
            # Poinformuj innych o nowym użytkowniku
            await broadcast("user_status_update", {"username": username, "status": "online"},
                            exclude_websocket=websocket)
            return True


async def handle_chat_message(client_info, message_text):
    global MESSAGE_COUNTER
    username = client_info.get("username")
    if not username:
        logging.warning("Otrzymano wiadomość od niezalogowanego klienta.")
        return

    with users_lock:
        user_data = USERS.get(username)
        if not user_data or "blocked" in user_data["account_status"]:
            await send_encrypted(client_info["websocket"], client_info["session_key"], "server_info",
                                 {"message": "Nie możesz wysyłać wiadomości (konto zablokowane)."})
            return

    with messages_lock:
        MESSAGE_COUNTER += 1
        timestamp = get_current_timestamp()
        message = {
            "id": MESSAGE_COUNTER,
            "timestamp": timestamp,
            "author": username,
            "text": message_text,
            "flags": []
        }
        MESSAGES.append(message)
        # Rozsyłamy tylko payload wiadomości czatu
        await broadcast("chat_message", message)
        logging.info(f"Wiadomość od {username}: {message_text}")


async def handle_get_history(client_info, count):
    username = client_info.get("username")
    if not username: return

    try:
        count = int(count)
        if count <= 0: count = 10  # Domyślna wartość
    except ValueError:
        count = 10

    with messages_lock:
        # Filtrujemy wiadomości bez flagi 'hidden' (chyba że admin by chciał widzieć wszystkie)
        visible_messages = [msg for msg in MESSAGES if "hidden" not in msg["flags"]]
        history = visible_messages[-count:]

    await send_encrypted(client_info["websocket"], client_info["session_key"], "message_history", {"messages": history})


# --- Główny Handler Połączeń WebSocket ---

async def handler(websocket, path):
    remote_addr = websocket.remote_address
    logging.info(f"Nowe połączenie od: {remote_addr}")
    client_info = {"websocket": websocket, "session_key": None, "username": None}

    try:
        # 1. Oczekiwanie na żądanie klucza publicznego
        message_raw = await websocket.recv()
        message = json.loads(message_raw)
        if message.get("type") == "get_public_key":
            await websocket.send(json.dumps({"type": "public_key", "key": SERVER_PUBLIC_KEY_PEM.decode('utf-8')}))
        else:
            logging.warning(f"Nieoczekiwana pierwsza wiadomość od {remote_addr}: {message.get('type')}")
            await websocket.close(reason="Invalid initial message")
            return

        # 2. Oczekiwanie na zaszyfrowany klucz sesji
        message_raw = await websocket.recv()
        message = json.loads(message_raw)
        if message.get("type") == "session_key":
            encrypted_key_b64 = message.get("key")
            session_key = decrypt_session_key(encrypted_key_b64)
            if session_key:
                client_info["session_key"] = session_key
                logging.info(f"Ustanowiono klucz sesji dla {remote_addr}")
                with clients_lock:
                    CLIENTS[websocket] = client_info  # Dodaj klienta do aktywnych połączeń
            else:
                logging.error(f"Nie udało się odszyfrować klucza sesji od {remote_addr}")
                await websocket.close(reason="Session key decryption failed")
                return
        else:
            logging.warning(f"Nieoczekiwana druga wiadomość od {remote_addr}: {message.get('type')}")
            await websocket.close(reason="Expected session key")
            return

        # 3. Pętla obsługi wiadomości po ustanowieniu sesji
        async for message_raw in websocket:
            try:
                # Odbieramy zaszyfrowaną wiadomość
                wrapper_message = json.loads(message_raw)
                if wrapper_message.get("type") != "encrypted_message":
                    logging.warning(f"Otrzymano niezaszyfrowaną wiadomość od {remote_addr} po ustanowieniu sesji.")
                    continue

                encrypted_data = wrapper_message.get("data")
                decrypted_json = decrypt_message_aes(client_info["session_key"], encrypted_data)

                if not decrypted_json:
                    logging.warning(f"Nie udało się odszyfrować wiadomości od {remote_addr}")
                    continue  # Ignoruj błędną wiadomość

                message = json.loads(decrypted_json)
                msg_type = message.get("type")
                payload = message.get("payload", {})

                # Logika obsługi różnych typów wiadomości
                if msg_type == "login":
                    username = payload.get("username")
                    password = payload.get("password")
                    if username and password:
                        if not await handle_login(websocket, client_info, username, password):
                            # Login failed (e.g., banned, wrong pass), connection closed in handle_login
                            return  # Zakończ handler dla tego klienta
                    else:
                        logging.warning(f"Niekompletne dane logowania od {remote_addr}")
                        await send_encrypted(websocket, client_info["session_key"], "login_status",
                                             {"success": False, "message": "Brak nazwy użytkownika lub hasła."})


                elif msg_type == "chat_message":
                    if client_info.get("username"):  # Tylko zalogowani mogą pisać
                        await handle_chat_message(client_info, payload.get("text"))
                    else:
                        logging.warning(f"Próba wysłania wiadomości przez niezalogowanego klienta {remote_addr}")
                        await send_encrypted(websocket, client_info["session_key"], "server_info",
                                             {"message": "Musisz się zalogować, aby wysyłać wiadomości."})

                elif msg_type == "get_history":
                    if client_info.get("username"):
                        await handle_get_history(client_info, payload.get("count", 10))
                    else:
                        logging.warning(f"Próba pobrania historii przez niezalogowanego klienta {remote_addr}")
                        await send_encrypted(websocket, client_info["session_key"], "server_info",
                                             {"message": "Musisz się zalogować, aby pobrać historię."})


                else:
                    logging.warning(
                        f"Nieznany typ wiadomości '{msg_type}' od {client_info.get('username', remote_addr)}")

            except json.JSONDecodeError:
                logging.error(f"Błąd dekodowania JSON od {client_info.get('username', remote_addr)}")
            except Exception as e:
                logging.error(f"Błąd przetwarzania wiadomości od {client_info.get('username', remote_addr)}: {e}",
                              exc_info=True)


    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"Klient {client_info.get('username', remote_addr)} rozłączył się.")
    except websockets.exceptions.ConnectionClosedError as e:
        logging.warning(f"Połączenie z {client_info.get('username', remote_addr)} zamknięte z błędem: {e}")
    except Exception as e:
        logging.error(f"Nieoczekiwany błąd w handlerze dla {client_info.get('username', remote_addr)}: {e}",
                      exc_info=True)
    finally:
        # --- Sprzątanie po rozłączeniu klienta ---
        username = client_info.get("username")
        if username:
            with users_lock:
                if username in USERS:
                    USERS[username]["last_online"] = get_current_timestamp()
                    USERS[username]["websocket"] = None  # Usuń referencję do websocket
                    logging.info(f"Użytkownik {username} offline.")
                    # Poinformuj innych o wylogowaniu
                    # Uruchom broadcast w pętli zdarzeń, bo jesteśmy w handlerze async
                    asyncio.create_task(broadcast("user_status_update", {"username": username, "status": "offline"},
                                                  exclude_websocket=websocket))

        with clients_lock:
            if websocket in CLIENTS:
                del CLIENTS[websocket]
        logging.info(f"Zakończono obsługę połączenia od {remote_addr}. Aktywnych klientów: {len(CLIENTS)}")


# --- Obsługa CLI ---
# Uruchamiana w osobnym wątku, żeby nie blokować asyncio

def cli_commands():
    global MESSAGE_COUNTER
    print("\nSerwer CLI uruchomiony. Wpisz 'help' po listę komend.")
    while True:
        try:
            cmd_line = input("> ").strip()
            if not cmd_line:
                continue

            parts = cmd_line.split()
            command = parts[0].lower()

            if command == "exit":
                print("Zamykanie serwera...")
                # Tutaj można dodać powiadomienie klientów i zamknięcie serwera asyncio
                os._exit(0)  # Twarde wyjście na potrzeby przykładu

            elif command == "help":
                print("Dostępne komendy:")
                print("  list users")
                print("  user [nazwa_usera]")
                print("  ban [nazwa_usera]")
                print("  noban [nazwa_usera]")
                print("  block [nazwa_usera]")
                print("  noblock [nazwa_usera]")
                print("  last [ilość_wiadomości]")
                print("  hide [numer_wiadomości]")
                print("  nohide [numer_wiadomości]")
                print("  exit")

            elif command == "list" and len(parts) > 1 and parts[1] == "users":
                with users_lock:
                    print("\n--- Lista Użytkowników ---")
                    print(f"{'Nazwa':<20} {'Status':<10} {'Ostatnio Online':<20} {'Status Konta'}")
                    print("-" * 70)
                    for name, data in USERS.items():
                        status = "online" if data.get("websocket") else "offline"
                        last_online = data.get("last_online", "N/A")
                        account_status = ", ".join(data.get("account_status", ["N/A"]))
                        print(f"{name:<20} {status:<10} {last_online:<20} {account_status}")
                    print("-" * 70)

            elif command == "user" and len(parts) > 1:
                username = parts[1]
                with users_lock:
                    user_data = USERS.get(username)
                if user_data:
                    print(f"\n--- Dane użytkownika: {username} ---")
                    status = "online" if user_data.get("websocket") else "offline"
                    print(f"  Status: {status}")
                    print(f"  Ostatnio Online: {user_data.get('last_online', 'N/A')}")
                    print(f"  Data Rejestracji: {user_data.get('registration_date', 'N/A')}")
                    print(f"  Status Konta: {', '.join(user_data.get('account_status', []))}")
                    print("  Wiadomości:")
                    with messages_lock:
                        user_messages = [msg for msg in MESSAGES if msg['author'] == username]
                        if user_messages:
                            for msg in user_messages:
                                flags = f" [{','.join(msg['flags'])}]" if msg['flags'] else ""
                                print(f"    [{msg['id']}] {msg['timestamp']} {msg['text']}{flags}")
                        else:
                            print("    Brak wiadomości.")
                    print("-" * 40)
                else:
                    print(f"Użytkownik '{username}' nie znaleziony.")

            elif command == "ban" and len(parts) > 1:
                username = parts[1]
                with users_lock:
                    if username in USERS:
                        if "banned" not in USERS[username]["account_status"]:
                            USERS[username]["account_status"].append("banned")
                            print(f"Użytkownik '{username}' został zbanowany.")
                            # Rozłącz jeśli jest online
                            ws = USERS[username].get("websocket")
                            if ws:
                                asyncio.run_coroutine_threadsafe(
                                    send_encrypted(ws, USERS[username]["session_key"], "server_info",
                                                   {"message": "Zostałeś zbanowany przez administratora."}),
                                    asyncio.get_event_loop()
                                )
                                asyncio.run_coroutine_threadsafe(
                                    ws.close(reason="Banned by admin"),
                                    asyncio.get_event_loop()
                                )
                        else:
                            print(f"Użytkownik '{username}' już jest zbanowany.")
                    else:
                        print(f"Użytkownik '{username}' nie znaleziony.")

            elif command == "noban" and len(parts) > 1:
                username = parts[1]
                with users_lock:
                    if username in USERS:
                        if "banned" in USERS[username]["account_status"]:
                            USERS[username]["account_status"].remove("banned")
                            print(f"Zdjęto bana użytkownikowi '{username}'.")
                        else:
                            print(f"Użytkownik '{username}' nie był zbanowany.")
                    else:
                        print(f"Użytkownik '{username}' nie znaleziony.")

            elif command == "block" and len(parts) > 1:
                username = parts[1]
                with users_lock:
                    if username in USERS:
                        if "blocked" not in USERS[username]["account_status"]:
                            USERS[username]["account_status"].append("blocked")
                            print(f"Zablokowano pisanie użytkownikowi '{username}'.")
                            ws = USERS[username].get("websocket")
                            if ws:
                                asyncio.run_coroutine_threadsafe(
                                    send_encrypted(ws, USERS[username]["session_key"], "server_info", {
                                        "message": "Możliwość pisania została zablokowana przez administratora."}),
                                    asyncio.get_event_loop()
                                )
                        else:
                            print(f"Użytkownik '{username}' już ma zablokowane pisanie.")
                    else:
                        print(f"Użytkownik '{username}' nie znaleziony.")

            elif command == "noblock" and len(parts) > 1:
                username = parts[1]
                with users_lock:
                    if username in USERS:
                        if "blocked" in USERS[username]["account_status"]:
                            USERS[username]["account_status"].remove("blocked")
                            print(f"Odblokowano pisanie użytkownikowi '{username}'.")
                            ws = USERS[username].get("websocket")
                            if ws:
                                asyncio.run_coroutine_threadsafe(
                                    send_encrypted(ws, USERS[username]["session_key"], "server_info", {
                                        "message": "Możliwość pisania została przywrócona przez administratora."}),
                                    asyncio.get_event_loop()
                                )
                        else:
                            print(f"Użytkownik '{username}' nie miał zablokowanego pisania.")
                    else:
                        print(f"Użytkownik '{username}' nie znaleziony.")


            elif command == "last" and len(parts) > 1:
                try:
                    count = int(parts[1])
                    with messages_lock:
                        # Pokazujemy wszystkie, łącznie z hidden, w CLI
                        last_msgs = MESSAGES[-count:]
                    print(f"\n--- Ostatnie {len(last_msgs)} wiadomości ---")
                    for msg in last_msgs:
                        flags = f" [{','.join(msg['flags'])}]" if msg['flags'] else ""
                        print(f"  [{msg['id']}] {msg['timestamp']} <{msg['author']}> {msg['text']}{flags}")
                    print("-" * 40)
                except ValueError:
                    print("Podaj poprawną liczbę wiadomości.")
                except IndexError:
                    print("Podano nieprawidłowy zakres.")


            elif command == "hide" and len(parts) > 1:
                try:
                    msg_id = int(parts[1])
                    with messages_lock:
                        found = False
                        for msg in MESSAGES:
                            if msg['id'] == msg_id:
                                if "hidden" not in msg['flags']:
                                    msg['flags'].append("hidden")
                                    print(f"Wiadomość [{msg_id}] została ukryta.")
                                else:
                                    print(f"Wiadomość [{msg_id}] już jest ukryta.")
                                found = True
                                break
                        if not found:
                            print(f"Nie znaleziono wiadomości o ID {msg_id}.")
                except ValueError:
                    print("Podaj poprawny numer ID wiadomości.")

            elif command == "nohide" and len(parts) > 1:
                try:
                    msg_id = int(parts[1])
                    with messages_lock:
                        found = False
                        for msg in MESSAGES:
                            if msg['id'] == msg_id:
                                if "hidden" in msg['flags']:
                                    msg['flags'].remove("hidden")
                                    print(f"Wiadomość [{msg_id}] została pokazana.")
                                else:
                                    print(f"Wiadomość [{msg_id}] nie była ukryta.")
                                found = True
                                break
                        if not found:
                            print(f"Nie znaleziono wiadomości o ID {msg_id}.")
                except ValueError:
                    print("Podaj poprawny numer ID wiadomości.")

            else:
                print("Nieznana komenda. Wpisz 'help' po listę komend.")

        except EOFError:  # Ctrl+D
            print("\nZamykanie serwera (EOF)...")
            os._exit(0)
        except KeyboardInterrupt:  # Ctrl+C
            print("\nZamykanie serwera (Ctrl+C)...")
            os._exit(0)
        except Exception as e:
            print(f"\nWystąpił błąd w CLI: {e}")
            logging.error("Błąd w pętli CLI", exc_info=True)


# --- Główna funkcja startowa serwera ---

async def main(host, port, private_key_path):
    # Wczytaj hasło do klucza prywatnego
    key_password = getpass.getpass("Podaj hasło do klucza prywatnego serwera: ")
    if not load_server_keys(private_key_path, key_password):
        return  # Zakończ, jeśli klucze się nie załadowały

    # Uruchom CLI w osobnym wątku
    cli_thread = threading.Thread(target=cli_commands, daemon=True)
    cli_thread.start()

    # Uruchom serwer WebSocket
    logging.info(f"Serwer nasłuchuje na ws://{host}:{port}")
    async with websockets.serve(handler, host, port):
        await asyncio.Future()  # Działa wiecznie


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bezpieczny serwer czatu WebSocket")
    parser.add_argument("--port", type=int, default=8765, help="Port nasłuchu serwera")
    parser.add_argument("--host", default="localhost", help="Adres IP/host nasłuchu serwera")
    parser.add_argument("--key-file", default="server_private_key.pem",
                        help="Ścieżka do zaszyfrowanego klucza prywatnego PEM")
    # parser.add_argument("--data-dir", default="./data", help="Katalog na pliki danych (users, messages)") # Do dodania w pełnej wersji
    args = parser.parse_args()

    # Sprawdzenie istnienia pliku klucza
    if not os.path.exists(args.key_file):
        logging.error(f"Plik klucza prywatnego '{args.key_file}' nie istnieje. Wygeneruj go najpierw.")
    else:
        # Poprawka importu base64
        import base64

        try:
            asyncio.run(main(args.host, args.port, args.key_file))
        except KeyboardInterrupt:
            print("\nZamykanie serwera...")
        except Exception as e:
            logging.critical(f"Krytyczny błąd podczas uruchamiania serwera: {e}", exc_info=True)
