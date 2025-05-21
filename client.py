import sys
import json
import asyncio
import websockets
import threading
import socket
import os
import base64
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QLineEdit, QTextEdit, QTabWidget, QSpinBox,
                             QMessageBox, QStyleFactory)
from PyQt6.QtCore import pyqtSignal, QObject, QThread, Qt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# --- Klasa do obsługi komunikacji sieciowej w osobnym wątku ---

class NetworkHandler(QThread):
    # Sygnały emitowane do głównego wątku GUI
    connection_status = pyqtSignal(str)  # "Connecting", "Connected", "Key Exchange", "Auth Required", "Logged In", "Disconnected", "Error: ..."
    message_received = pyqtSignal(dict)  # Przekazuje odszyfrowany payload wiadomości
    login_result = pyqtSignal(bool, str)  # Sukces/porażka, wiadomość

    session_and_public_key = pyqtSignal(str, str)  # Klucz sesji i klucz publiczny serwera
    encrypted_message = pyqtSignal(str)  # Zaszyfrowana wiadomość

    def __init__(self, server_uri):
        super().__init__()
        self.server_uri = server_uri
        self.websocket = None
        self.server_public_key = None
        self.session_key = None
        self.is_running = False
        self.event_loop = None  # Pętla zdarzeń dla tego wątku

    def set_server_uri(self, uri):
        self.server_uri = uri

    # --- Funkcje Kryptograficzne Klienta ---
    def _generate_session_key(self):
        self.session_key = AESGCM.generate_key(bit_length=256)
        #self.session_and_public_key.emit(None, base64.b64encode(self.session_key).decode('utf-8')) 
        self.session_and_public_key.emit(None, base64.b64encode(self.session_key).decode('utf-8')) 
        
    def _encrypt_session_key(self):
        if not self.server_public_key or not self.session_key:
            return None
        try:
            encrypted_key = self.server_public_key.encrypt(
                self.session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted_key).decode('utf-8')
        except Exception as e:
            self.connection_status.emit(f"Error: Crypto (encrypt session key) failed: {e}")
            return None

    def encrypt_message(self, plaintext):
        if not self.session_key: return None
        try:
            aesgcm = AESGCM(self.session_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            return base64.b64encode(nonce + ciphertext).decode('utf-8')
        except Exception as e:
            self.connection_status.emit(f"Error: Crypto (encrypt) failed: {e}")
            return None

    def decrypt_message(self, encrypted_data_b64):
        if not self.session_key: return None
        try:
            encrypted_data = base64.b64decode(encrypted_data_b64)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            aesgcm = AESGCM(self.session_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            self.connection_status.emit(f"Error: Crypto (decrypt/verify) failed: {e}")
            return None

    # --- Główna pętla wątku ---
    def run(self):
        self.is_running = True
        # Uruchom pętlę zdarzeń asyncio w tym wątku
        self.event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.event_loop)
        self.event_loop.run_until_complete(self.connect_and_listen())
        self.event_loop.close()
        self.is_running = False
        self.connection_status.emit("Disconnected")
        print("Network thread finished.")

    async def connect_and_listen(self):
        self.connection_status.emit("Connecting")
        try:
            #======Własny port klienta===========
            # local_port = 65000  # Wybierz dostępny port zgodny z polityką VPS
            # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # sock.bind(("0.0.0.0", local_port))  # Ustawienie portu klienta
            # sock.connect(("localhost", 8765))
            # async with websockets.connect(self.server_uri, sock=sock) as ws:
            async with websockets.connect(self.server_uri) as ws:
                self.websocket = ws
                self.connection_status.emit("Connected - Key Exchange")

                # 1. Poproś o klucz publiczny
                await ws.send(json.dumps({"type": "get_public_key"}))
                response_raw = await ws.recv()
                response = json.loads(response_raw)

                if response.get("type") == "public_key":
                    pem_public = response.get("key").encode('utf-8')
                    self.session_and_public_key.emit(response.get("key"), None)  # Emituj klucz publiczny
                    try:
                        self.server_public_key = serialization.load_pem_public_key(
                            pem_public,
                            backend=default_backend()
                        )
                    except Exception as e:
                        self.connection_status.emit(f"Error: Invalid public key received: {e}")
                        return  # Zakończ połączenie

                    # 2. Wygeneruj i wyślij klucz sesji
                    self._generate_session_key()
                    encrypted_session_key_b64 = self._encrypt_session_key()
                    if encrypted_session_key_b64:
                        await ws.send(json.dumps({"type": "session_key", "key": encrypted_session_key_b64}))
                        self.connection_status.emit("Auth Required")  # Gotowy do logowania
                    else:
                        self.connection_status.emit("Error: Failed to encrypt session key")
                        return  # Zakończ

                    # 3. Pętla nasłuchu
                    async for message_raw in ws:
                        if not self.is_running: break  # Zakończ, jeśli wątek ma być zatrzymany
                        try:
                            wrapper_message = json.loads(message_raw)
                            if wrapper_message.get("type") == "encrypted_message":
                                encrypted_data = wrapper_message.get("data")
                                decrypted_json = self.decrypt_message(encrypted_data)
                                if decrypted_json:
                                    message = json.loads(decrypted_json)
                                    message["encrypted"] = encrypted_data
                                    # Wyślij sygnał do GUI
                                    self.handle_server_message(message)
                                else:
                                    print("Failed to decrypt message from server")  # Log/status
                            else:
                                print(f"Received non-encrypted message from server: {wrapper_message.get('type')}")

                        except json.JSONDecodeError:
                            print("Error decoding server JSON")
                        except Exception as e:
                            print(f"Error processing server message: {e}")

                else:
                    self.connection_status.emit("Error: Expected public key from server")

        except websockets.exceptions.InvalidURI:
            self.connection_status.emit(f"Error: Invalid server address: {self.server_uri}")
        except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK) as e:
            self.connection_status.emit(
                f"Disconnected: {e.reason if hasattr(e, 'reason') else 'Server closed connection'}")
        except ConnectionRefusedError:
            self.connection_status.emit(f"Error: Connection refused by server at {self.server_uri}")
        except OSError as e:  # Np. [Errno 111] Connection refused
            self.connection_status.emit(f"Error: OS error ({e.strerror}) connecting to {self.server_uri}")
        except Exception as e:
            self.connection_status.emit(f"Error: Network exception: {e}")
        finally:
            self.websocket = None
            self.session_key = None
            self.server_public_key = None
            if self.is_running:  # Jeśli błąd nie był spowodowany zatrzymaniem wątku
                self.connection_status.emit("Disconnected")

    def handle_server_message(self, message):
        msg_type = message.get("type")
        payload = message.get("payload", {})

        if msg_type == "login_status":
            success = payload.get("success", False)
            info = payload.get("message", "")
            self.login_result.emit(success, info)
            if success:
                # Po udanym logowaniu zmień status
                self.connection_status.emit("Logged In")
        elif msg_type in ["chat_message", "message_history", "server_info", "user_status_update"]:
            # Przekaż całą wiadomość do GUI przez sygnał
            self.message_received.emit(message)
        else:
            print(f"Received unknown message type from server: {msg_type}")

    async def _send_message_async(self, message_type, payload):
        if self.websocket and self.session_key and self.is_running:
            message_json = json.dumps({"type": message_type, "payload": payload})
            encrypted_payload = self.encrypt_message(message_json)
            if encrypted_payload:
                try:
                    await self.websocket.send(json.dumps({"type": "encrypted_message", "data": encrypted_payload}))
                except websockets.exceptions.ConnectionClosed:
                    self.connection_status.emit("Error: Connection closed while sending")
                    self.stop()  # Zatrzymaj wątek, bo połączenie jest zamknięte
                except Exception as e:
                    print(f"Error sending message: {e}")
            else:
                print("Failed to encrypt message for sending")
        elif not self.is_running:
            print("Cannot send message, network thread is not running.")
        else:
            print("Cannot send message, not connected or session not established.")

    def send_message(self, message_type, payload):
        """Publiczna metoda do wywołania z głównego wątku GUI"""
        if self.event_loop and self.is_running:
            # Uruchom korutynę wysyłania w pętli zdarzeń wątku sieciowego
            asyncio.run_coroutine_threadsafe(
                self._send_message_async(message_type, payload),
                self.event_loop
            )


    def stop(self):
        print("Stopping network thread...")
        self.is_running = False
        if self.websocket:
            # Zamknij websocket z pętli zdarzeń wątku sieciowego
            if self.event_loop and self.event_loop.is_running():
                asyncio.run_coroutine_threadsafe(self.websocket.close(), self.event_loop)
            else:  # Spróbuj zamknąć synchronicznie jeśli pętla nie działa (mało prawdopodobne)
                try:
                    self.websocket.close_sync()
                except:
                    pass  # Ignoruj błędy przy zamykaniu
        # Czekanie na zakończenie wątku jest obsługiwane przez quit() i wait() w głównym oknie


# --- Główne Okno Aplikacji PyQt ---

class ChatClientWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bezpieczny Czat Klient")
        self.setGeometry(100, 100, 700, 500)

        # Domyślny styl systemowy
        QApplication.setStyle(QStyleFactory.create('Fusion'))  # Lub inny dostępny

        self.config = {"server_ip": "localhost", "server_port": 8765, "theme": "Default", "history_count": 50}
        self.load_config()  # Wczytaj, jeśli istnieje

        self.network_thread = None

        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        # Zakładki
        self.config_tab = QWidget()
        self.connection_tab = QWidget()
        self.login_tab = QWidget()
        self.chat_tab = QWidget()
        self.encrypted_data = QWidget()

        self.tab_widget.addTab(self.config_tab, "Konfiguracja")
        self.tab_widget.addTab(self.connection_tab, "Połączenie")
        self.tab_widget.addTab(self.login_tab, "Logowanie")
        self.tab_widget.addTab(self.chat_tab, "Czat")
        self.tab_widget.addTab(self.encrypted_data, "Dane Szyfrowania")

        self.init_config_tab()
        self.init_connection_tab()
        self.init_login_tab()
        self.init_chat_tab()
        self.init_encrypted_data_tab()

        self.update_ui_state("Disconnected")  # Początkowy stan

    # --- Inicjalizacja zakładek ---

    def init_config_tab(self):
        layout = QVBoxLayout(self.config_tab)
        form_layout = QHBoxLayout()

        self.server_ip_input = QLineEdit(self.config["server_ip"])
        self.server_port_input = QLineEdit(str(self.config["server_port"]))
        self.history_count_input = QSpinBox()
        self.history_count_input.setRange(1, 1000)
        self.history_count_input.setValue(self.config["history_count"])

        form_layout.addWidget(QLabel("Adres serwera:"))
        form_layout.addWidget(self.server_ip_input)
        form_layout.addWidget(QLabel("Port:"))
        form_layout.addWidget(self.server_port_input)
        form_layout.addWidget(QLabel("Ilość historii:"))
        form_layout.addWidget(self.history_count_input)

        save_button = QPushButton("Zapisz Konfigurację")
        save_button.clicked.connect(self.save_config_action)

        layout.addLayout(form_layout)
        layout.addWidget(save_button)
        layout.addStretch()

    def init_connection_tab(self):
        layout = QVBoxLayout(self.connection_tab)
        self.status_label = QLabel("Status: Rozłączony")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = self.status_label.font()
        font.setPointSize(14)
        self.status_label.setFont(font)

        self.connect_button = QPushButton("Połącz")
        self.disconnect_button = QPushButton("Rozłącz")

        self.connect_button.clicked.connect(self.connect_action)
        self.disconnect_button.clicked.connect(self.disconnect_action)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.connect_button)
        button_layout.addWidget(self.disconnect_button)

        layout.addWidget(self.status_label)
        layout.addLayout(button_layout)
        layout.addStretch()

    def init_login_tab(self):
        layout = QVBoxLayout(self.login_tab)
        self.login_status_label = QLabel("")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Nazwa użytkownika")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Hasło")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_button = QPushButton("Zaloguj / Zarejestruj")
        self.login_button.clicked.connect(self.login_action)

        layout.addWidget(QLabel("Podaj dane logowania:"))
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.login_status_label)
        layout.addStretch()

    def init_chat_tab(self):
        layout = QVBoxLayout(self.chat_tab)

        # Menu po prawej (symulowane przez QHBoxLayout)
        top_layout = QHBoxLayout()
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)

        # Panel boczny (menu)
        menu_widget = QWidget()
        menu_layout = QVBoxLayout(menu_widget)
        menu_widget.setFixedWidth(150)  # Szerokość panelu

        self.refresh_history_count_input = QSpinBox()
        self.refresh_history_count_input.setRange(1, 1000)
        self.refresh_history_count_input.setValue(self.config["history_count"])
        refresh_button = QPushButton("Odśwież Historię")
        refresh_button.clicked.connect(self.refresh_history_action)

        menu_layout.addWidget(QLabel("Ilość wiadomości:"))
        menu_layout.addWidget(self.refresh_history_count_input)
        menu_layout.addWidget(refresh_button)
        menu_layout.addStretch()

        top_layout.addWidget(self.chat_display)  # Główny obszar czatu
        top_layout.addWidget(menu_widget)  # Panel boczny

        # Dolna część do wpisywania
        bottom_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Wpisz wiadomość...")
        self.send_button = QPushButton("Wyślij")
        self.send_button.clicked.connect(self.send_message_action)
        self.message_input.returnPressed.connect(self.send_button.click)  # Wyślij Enterem

        bottom_layout.addWidget(self.message_input)
        bottom_layout.addWidget(self.send_button)

        layout.addLayout(top_layout)
        layout.addLayout(bottom_layout)

    # Zakładka zawiera trzy pola tekstowe tylko do odczytu: obecny klucz sesji, klucz publiczny serwera i zaszyfrowana wiadomość
    def init_encrypted_data_tab(self):
        layout = QVBoxLayout(self.encrypted_data)
        self.session_key_display = QTextEdit()
        self.session_key_display.setReadOnly(True)
        self.server_public_key_display = QTextEdit()
        self.server_public_key_display.setReadOnly(True)
        self.encrypted_message_display = QTextEdit()
        self.encrypted_message_display.setReadOnly(True)

        layout.addWidget(QLabel("Obecny klucz sesji:"))
        layout.addWidget(self.session_key_display)
        layout.addWidget(QLabel("Klucz publiczny serwera:"))
        layout.addWidget(self.server_public_key_display)
        layout.addWidget(QLabel("Zaszyfrowana wiadomość:"))
        layout.addWidget(self.encrypted_message_display)



    # --- Akcje GUI ---

    def save_config_action(self):
        try:
            port = int(self.server_port_input.text())
            if not (0 < port < 65536):
                raise ValueError("Port musi być liczbą między 1 a 65535")
            self.config["server_ip"] = self.server_ip_input.text()
            self.config["server_port"] = port
            self.config["history_count"] = self.history_count_input.value()
            self.save_config()
            QMessageBox.information(self, "Konfiguracja", "Konfiguracja zapisana.")
        except ValueError as e:
            QMessageBox.warning(self, "Błąd Konfiguracji", f"Nieprawidłowe dane: {e}")

    def connect_action(self):
        if self.network_thread and self.network_thread.isRunning():
            print("Already connected or connecting.")
            return

        server_ip = self.config["server_ip"]
        server_port = self.config["server_port"]
        uri = f"ws://{server_ip}:{server_port}"

        self.network_thread = NetworkHandler(uri)
        # Połącz sygnały z wątku sieciowego do slotów w GUI
        self.network_thread.connection_status.connect(self.handle_connection_status)
        self.network_thread.message_received.connect(self.handle_message_received)
        self.network_thread.login_result.connect(self.handle_login_result)
        self.network_thread.session_and_public_key.connect(self.handle_session_and_public_key)
        self.network_thread.finished.connect(self.network_thread_finished)  # Sprzątanie po zakończeniu wątku

        self.network_thread.start()
        self.update_ui_state("Connecting")

    def disconnect_action(self):
        if self.network_thread and self.network_thread.isRunning():
            self.network_thread.stop()  # Sygnalizuje zatrzymanie i próbuje zamknąć socket
            # update_ui_state nastąpi po sygnale finished lub connection_status("Disconnected")
        else:
            print("Not connected.")

    def login_action(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            self.login_status_label.setText("Nazwa użytkownika i hasło są wymagane.")
            return

        if self.network_thread and self.network_thread.isRunning() and self.network_thread.session_key:
            self.login_status_label.setText("Logowanie...")
            self.network_thread.send_message("login", {"username": username, "password": password})
        else:
            self.login_status_label.setText("Nie połączono lub brak sesji.")

    def send_message_action(self):
        message_text = self.message_input.text().strip()
        if not message_text:
            return

        if self.network_thread and self.network_thread.isRunning():
            self.network_thread.send_message("chat_message", {"text": message_text})
            self.message_input.clear()
        else:
            self.append_chat_message("[System]", "Nie jesteś połączony.")

    def refresh_history_action(self):
        count = self.refresh_history_count_input.value()
        if self.network_thread and self.network_thread.isRunning():
            self.chat_display.clear()  # Czyścimy przed nową historią
            self.append_chat_message("[System]", f"Pobieranie ostatnich {count} wiadomości...")
            self.network_thread.send_message("get_history", {"count": count})
        else:
            self.append_chat_message("[System]", "Nie jesteś połączony.")

    # --- Sloty obsługujące sygnały z NetworkHandler ---

    def handle_connection_status(self, status):
        self.status_label.setText(f"Status: {status}")
        print(f"Connection status update: {status}")
        self.update_ui_state(status)  # Aktualizuj stan GUI

    def handle_login_result(self, success, message):
        self.login_status_label.setText(message)
        if success:
            # Stan "Logged In" zostanie ustawiony przez handle_connection_status
            # Możemy od razu pobrać historię po zalogowaniu
            self.refresh_history_action()
            self.tab_widget.setCurrentWidget(self.chat_tab)  # Przełącz na czat
        else:
            # Pozwól użytkownikowi spróbować ponownie
            self.login_button.setEnabled(True)


    def handle_message_received(self, message):
        msg_type = message.get("type")
        payload = message.get("payload", {})

        #wyswietl zaszyfrowaną wiadomość
        if message.get("encrypted"):
            self.encrypted_message_display.setPlainText(message.get("encrypted"))

        if msg_type == "chat_message":
            author = payload.get("author", "Unknown")
            text = payload.get("text", "")
            timestamp = payload.get("timestamp", "")  # Można sformatować czas
            time_str = timestamp.split()[-1] if timestamp else ""
            self.append_chat_message(f"[{time_str}] <{author}>", text)

        elif msg_type == "message_history":
            messages = payload.get("messages", [])
            # self.chat_display.clear() # Zwykle czyścimy przed pobraniem historii w refresh_history_action
            self.append_chat_message("[System]", "--- Historia Wiadomości ---")
            for msg in messages:
                author = msg.get("author", "Unknown")
                text = msg.get("text", "")
                timestamp = msg.get("timestamp", "")
                time_str = timestamp.split()[-1] if timestamp else ""
                self.append_chat_message(f"[{time_str}] <{author}>", text)
            self.append_chat_message("[System]", "--- Koniec Historii ---")


        elif msg_type == "server_info":
            info = payload.get("message", "")
            self.append_chat_message("[Server]", info)

        elif msg_type == "user_status_update":
            username = payload.get("username", "Unknown")
            status = payload.get("status", "unknown")
            self.append_chat_message("[System]", f"Użytkownik {username} jest teraz {status}.")

    def handle_session_and_public_key(self, public_key, session_key):
        if public_key:
            self.server_public_key_display.setPlainText(public_key)
        if session_key:
            self.session_key_display.setPlainText(session_key)

    def append_chat_message(self, prefix, message):
        # Dodaje wiadomość do QTextEdit, przewijając na dół
        self.chat_display.append(f"{prefix}: {message}")
        self.chat_display.verticalScrollBar().setValue(self.chat_display.verticalScrollBar().maximum())


    def network_thread_finished(self):
        print("Network thread has finished.")
        # Upewnij się, że stan UI jest poprawny po zakończeniu wątku
        if "Error" not in self.status_label.text():  # Jeśli nie zakończył się błędem
            self.update_ui_state("Disconnected")


    # --- Zarządzanie stanem GUI ---

    def update_ui_state(self, status_string):
        # Domyślnie wszystko zablokowane
        is_connecting = "Connecting" in status_string
        is_connected_no_auth = "Connected" in status_string or "Key Exchange" in status_string
        is_auth_required = "Auth Required" in status_string
        is_logged_in = "Logged In" in status_string
        is_disconnected = "Disconnected" in status_string or "Error" in status_string

        # Zakładka Konfiguracji - zawsze dostępna
        self.tab_widget.setTabEnabled(0, True)

        # Zakładka Połączenia
        self.tab_widget.setTabEnabled(1, True)
        self.connect_button.setEnabled(is_disconnected)
        self.disconnect_button.setEnabled(not is_disconnected and not is_connecting)

        # Zakładka Logowania
        can_login = is_auth_required or is_logged_in  # Można próbować się zalogować ponownie jeśli jest już zalogowany? Może nie.
        self.tab_widget.setTabEnabled(2, can_login)
        self.username_input.setEnabled(can_login)
        self.password_input.setEnabled(can_login)
        self.login_button.setEnabled(can_login)
        if is_disconnected: self.login_status_label.setText("")  # Wyczyść status logowania po rozłączeniu

        # Zakładka Czatu
        self.tab_widget.setTabEnabled(3, is_logged_in)
        self.message_input.setEnabled(is_logged_in)
        self.send_button.setEnabled(is_logged_in)
        # Przycisk odświeżania historii też tylko po zalogowaniu
        self.chat_tab.findChild(QPushButton, "refresh_button")  # Proste wyszukanie, można lepiej
        refresh_btn = self.chat_tab.findChild(QPushButton)  # Zakładając, że to jedyny QPushButton w menu
        if refresh_btn and refresh_btn.text() == "Odśwież Historię":
            refresh_btn.setEnabled(is_logged_in)

        # Przełącz na odpowiednią zakładkę
        if is_auth_required and self.tab_widget.currentIndex() < 2:
            self.tab_widget.setCurrentWidget(self.login_tab)
        elif is_logged_in and self.tab_widget.currentIndex() < 3:
            self.tab_widget.setCurrentWidget(self.chat_tab)
        elif is_disconnected and self.tab_widget.currentIndex() > 1:
            self.tab_widget.setCurrentWidget(self.connection_tab)


    # --- Konfiguracja Plików ---
    def get_config_path(self):
        # Zapisz konfigurację w katalogu domowym użytkownika
        home = os.path.expanduser("~")
        config_dir = os.path.join(home, ".secure_chat_client")
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, "config.json")


    def load_config(self):
        config_path = self.get_config_path()
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                    # Sprawdź czy klucze istnieją i mają sensowne typy
                    if isinstance(loaded_config.get("server_ip"), str):
                        self.config["server_ip"] = loaded_config["server_ip"]
                    if isinstance(loaded_config.get("server_port"), int):
                        self.config["server_port"] = loaded_config["server_port"]
                    if isinstance(loaded_config.get("theme"), str):
                        self.config["theme"] = loaded_config["theme"]  # Motyw niezaimplementowany w GUI
                    if isinstance(loaded_config.get("history_count"), int):
                        self.config["history_count"] = loaded_config["history_count"]

        except (json.JSONDecodeError, IOError) as e:
            print(f"Could not load config file: {e}")
        except Exception as e:
            print(f"Unexpected error loading config: {e}")


    def save_config(self):
        config_path = self.get_config_path()
        try:
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except IOError as e:
            print(f"Could not save config file: {e}")
        except Exception as e:
            print(f"Unexpected error saving config: {e}")


    # --- Zamykanie aplikacji ---
    def closeEvent(self, event):
        """Obsługa zamknięcia okna."""
        self.disconnect_action()  # Spróbuj się rozłączyć
        if self.network_thread and self.network_thread.isRunning():
            self.network_thread.wait(1000)  # Poczekaj chwilę na zakończenie wątku sieciowego
        self.save_config()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatClientWindow()
    window.show()
    sys.exit(app.exec())
