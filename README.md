import sys
import socket
import psutil
import datetime
import os

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget,
    QTextEdit, QPushButton, QLabel, QMessageBox
)
from PyQt5.QtCore import QTimer


class CyberSecurityGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberSecurity Tool")
        self.setGeometry(100, 100, 800, 600)

        # Марказий виджет
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Маълумот чиқариш ойнаси
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)

        # Тугмалар
        self.btn_connections = QPushButton("Фаол уланишларни кўрсат")
        self.btn_connections.clicked.connect(self.show_active_connections)
        layout.addWidget(self.btn_connections)

        self.btn_ports = QPushButton("Очик портларни сканерлаш (1-1024)")
        self.btn_ports.clicked.connect(self.scan_ports)
        layout.addWidget(self.btn_ports)

        self.btn_system = QPushButton("Тизим маълумоти")
        self.btn_system.clicked.connect(self.show_system_info)
        layout.addWidget(self.btn_system)

        # Статус
        self.status_label = QLabel("Тайёр")
        layout.addWidget(self.status_label)

        # Яширин режим
        if len(sys.argv) > 1 and sys.argv[1] == "--hidden":
            self.hide()
            self.start_hidden_mode()

    def log_message(self, msg):
        """Ойнага ва файлга лог ёзиш"""
        self.text_area.append(msg)
        if hasattr(self, 'hidden_log_file'):
            with open(self.hidden_log_file, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.datetime.now()} - {msg}\n")

    def show_active_connections(self):
        """Фаол уланишлар"""
        self.log_message("\n=== Фаол уланишлар ===")
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                self.log_message(f"{laddr} -> {raddr} ({conn.status})")
        self.status_label.setText("Уланишлар кўрсатилди")

    def scan_ports(self):
        """Порт скан"""
        self.log_message("\n=== Очик портлар (1-1024) ===")
        open_ports = []

        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        if open_ports:
            self.log_message(f"Топилган портлар: {open_ports}")
        else:
            self.log_message("Очик порт топилмади.")

        self.status_label.setText("Сканер тугади")

    def show_system_info(self):
        """Тизим маълумоти"""
        self.log_message("\n=== Тизим маълумоти ===")
        self.log_message(f"Хост: {socket.gethostname()}")
        self.log_message(f"IP: {socket.gethostbyname_ex(socket.gethostname())}")
        self.log_message(f"CPU: {psutil.cpu_percent()}%")
        self.log_message(f"RAM: {psutil.virtual_memory().percent}%")
        self.status_label.setText("Маълумот кўрсатилди")

    def start_hidden_mode(self):
        """Яширин режим"""
        if not os.path.exists("logs"):
            os.makedirs("logs")

        self.hidden_log_file = f"logs/connections_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        self.timer = QTimer()
        self.timer.timeout.connect(self.hidden_log_connections)
        self.timer.start(30000)

        self.status_label.setText("Яширин режим...")

    def hidden_log_connections(self):
        """Яширин лог"""
        with open(self.hidden_log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n--- {datetime.datetime.now()} ---\n")
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    f.write(f"{laddr} -> {raddr}\n")

    def closeEvent(self, event):
        if hasattr(self, 'timer'):
            self.timer.stop()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CyberSecurityGUI()

    if not (len(sys.argv) > 1 and sys.argv[1] == "--hidden"):
        window.show()

    sys.exit(app.exec_())
