import sys
import re
from threading import Thread, Event
from multiprocessing import Pool
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
                             QPushButton, QProgressBar, QTextEdit, QSizePolicy, QLabel)
from PyQt6.QtCore import pyqtSignal, pyqtSlot, Qt
from PyQt6.QtGui import QTextCursor
from config import OUTPUT_DIR, console
from utils import check_and_install_tools, ensure_wordlists
from scanning import (
    amass_subdomain_enumeration, sublist3r_subdomain_enumeration, theharvester_osint, nmap_scan,
    gobuster_directory_scan, nikto_scan, wpscan_scan, sqlmap_scan, jsparser_scan, ffuf_fuzzing,
    searchsploit_scan, enum4linux_scan, hydra_brute_force
)
from results import extract_info_from_nmap, extract_directories_from_gobuster

def worker(func, arg):
    return func(arg)

class ScannerThread(Thread):
    update_signal = pyqtSignal(str)

    def __init__(self, target_domain: str, update_signal: pyqtSignal):
        super().__init__()
        self.target_domain = target_domain
        self.update_signal = update_signal
        self._stop_event = Event()
        self._skip_event = Event()

    def run(self):
        try:
            check_and_install_tools()
            ensure_wordlists()

            # Define tasks as a list of tuples without using lambda
            tasks = [
                (amass_subdomain_enumeration, self.target_domain),
                (sublist3r_subdomain_enumeration, self.target_domain),
                (theharvester_osint, self.target_domain),
                (nmap_scan, self.target_domain)
            ]

            with Pool(processes=4) as pool:
                results = pool.starmap(worker, tasks)
                nmap_output = results[3]
                services, service_versions = extract_info_from_nmap(nmap_output)

            if self._stop_event.is_set():
                self.update_signal.emit("[bold red]Scanning stopped.[/bold red]")
                return

            http_services = [service for service in services if 'http' in service.lower()]
            if http_services:
                gobuster_output = gobuster_directory_scan(self.target_domain)
                directories = extract_directories_from_gobuster(gobuster_output)
                nikto_scan(self.target_domain)

                if self._stop_event.is_set():
                    self.update_signal.emit("[bold red]Scanning stopped.[/bold red]")
                    return

                if any('wp-' in directory for directory in directories):
                    wpscan_scan(self.target_domain)

                sql_injection_candidates = [directory for directory in directories if
                                            re.search(r'\b(login|search|id)\b', directory)]
                if sql_injection_candidates:
                    sqlmap_scan(self.target_domain, sql_injection_candidates)

                js_files = [directory for directory in directories if directory.endswith('.js')]
                if js_files:
                    jsparser_scan(self.target_domain, js_files)

                ffuf_fuzzing(self.target_domain)
            else:
                directories = []

            if self._stop_event.is_set():
                self.update_signal.emit("[bold red]Scanning stopped.[/bold red]")
                return

            searchsploit_scan(services, self.target_domain)

            smb_services = [service for service in services if 'smb' in service.lower() or 'netbios' in service.lower()]
            if smb_services:
                enum4linux_scan(self.target_domain)

            login_directories = [directory for directory in directories if 'login' in directory]
            if login_directories:
                hydra_brute_force(self.target_domain, login_directories)

            if not self._stop_event.is_set():
                self.update_signal.emit(f"\n[bold green]Scanning and enumeration completed. Results saved in {OUTPUT_DIR}[/bold green]")
        except Exception as e:
            self.update_signal.emit(f"[bold red]An error occurred: {str(e)}[/bold red]")

    def stop(self):
        self._stop_event.set()

    def skip(self):
        self._skip_event.set()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Modern Security Scanner")
        self.setGeometry(100, 100, 1200, 800)

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)

        self.layout = QVBoxLayout()
        self.main_widget.setLayout(self.layout)

        self.init_ui()
        self.apply_styles()

    def init_ui(self):
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target URL (without http/https)")
        self.layout.addWidget(self.url_input)

        self.buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.skip_button = QPushButton("Skip")
        self.buttons_layout.addWidget(self.start_button)
        self.buttons_layout.addWidget(self.stop_button)
        self.buttons_layout.addWidget(self.skip_button)
        self.layout.addLayout(self.buttons_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.layout.addWidget(self.progress_bar)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.layout.addWidget(self.log_view)

        self.info_label = QLabel()
        self.layout.addWidget(self.info_label)

        self.start_button.clicked.connect(self.start_scanning)
        self.stop_button.clicked.connect(self.stop_scanning)
        self.skip_button.clicked.connect(self.skip_task)

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QLineEdit {
                padding: 10px;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
                background-color: #3a3a3a;
                color: #ffffff;
            }
            QPushButton {
                padding: 10px;
                border: none;
                border-radius: 5px;
                background-color: #3a3a3a;
                color: #ffffff;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QPushButton:pressed {
                background-color: #5a5a5a;
            }
            QProgressBar {
                text-align: center;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
                background-color: #3a3a3a;
                color: #ffffff;
            }
            QTextEdit {
                padding: 10px;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
                background-color: #3a3a3a;
                color: #ffffff;
            }
            QLabel {
                font-weight: bold;
                font-size: 16px;
            }
        """)

    def start_scanning(self):
        url = self.url_input.text().strip()
        if url.startswith("http://"):
            url = url[len("http://"):]
        elif url.startswith("https://"):
            url = url[len("https://"):]

        if not url:
            self.update_log("[bold red]URL cannot be empty.[/bold red]")
            return

        self.thread = ScannerThread(url, self.update_log)
        self.thread.start()
        self.progress_bar.setValue(0)
        self.info_label.setText("Scanning in progress...")

    def stop_scanning(self):
        if hasattr(self, 'thread') and self.thread.is_alive():
            self.thread.stop()
            self.update_log("[bold red]Scanning stopped.[/bold red]")
            self.info_label.setText("Scanning stopped.")

    def skip_task(self):
        if hasattr(self, 'thread') and self.thread.is_alive():
            self.thread.skip()
            self.update_log("[bold yellow]Task skipped.[/bold yellow]")
            self.info_label.setText("Task skipped.")

    @pyqtSlot(str)
    def update_log(self, message):
        self.log_view.append(message)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)
        # Update progress bar based on task progress (if applicable)
        # self.progress_bar.setValue(new_value)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())
