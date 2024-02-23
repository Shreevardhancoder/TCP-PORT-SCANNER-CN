import socket
import sys
import ssl
import pyfiglet
from rich.console import Console
from rich.table import Table
from utils import extract_json_data, threadpool_executer

console = Console()


class PScan:

    PORTS_DATA_FILE = "./common_ports.json"

    def __init__(self):
        self.ports_info = {}
        self.open_ports = []
        self.remote_host = ""

    def get_ports_info(self):
        data = extract_json_data(PScan.PORTS_DATA_FILE)
        self.ports_info = {int(k): v for (k, v) in data.items()}

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        conn_status = sock.connect_ex((self.remote_host, port))
        if conn_status == 0:
            if port in self.ports_info:
                service = self.ports_info[port]
            else:
                service = "Unknown"
            # Check if the connection is secure
            is_secure = self.check_secure_connection(port)
            self.open_ports.append((port, service, is_secure))
        sock.close()

    def check_secure_connection(self, port):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.remote_host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.remote_host) as ssock:
                    return True
        except (ssl.CertificateError, ssl.SSLError, ConnectionRefusedError):
            return False

    def show_completion_message(self):
        print()
        if self.open_ports:
            console.print("Scan Completed. Open Ports:", style="bold blue")
            table = Table(show_header=True, header_style="bold green")
            table.add_column("PORT", style="blue")
            table.add_column("STATE", style="blue", justify="center")
            table.add_column("SERVICE", style="blue")
            table.add_column("SECURE", style="blue")
            for port_info in self.open_ports:
                port, service, is_secure = port_info
                state = "OPEN"
                secure_status = "YES" if is_secure else "NO"
                table.add_row(str(port), state, service, secure_status)
            console.print(table)
        else:
            console.print(f"No Open Ports Found on Target", style="bold magenta")

    @staticmethod
    def show_startup_message():
        ascii_art = pyfiglet.figlet_format("# PSCAN #")
        console.print(f"[bold green]{ascii_art}[/bold green]")
        console.print("#" * 55, style="bold green")
        console.print(
            "#" * 9, "Simple MultiThread TCP Port Scanner", "#" * 9, style="bold green"
        )
        console.print("#" * 55, style="bold green")
        print()

    @staticmethod
    def get_host_ip_addr(target):
        try:
            ip_addr = socket.gethostbyname(target)
        except socket.gaierror as e:
            console.print(f"{e}. Exiting.", style="bold red")
            sys.exit()
        console.print(f"\nIP address acquired: [bold blue]{ip_addr}[/bold blue]")
        return ip_addr

    def initialize(self):
        self.show_startup_message()
        self.get_ports_info()
        try:
            target = console.input("[bold blue]Target: ")
        except KeyboardInterrupt:
            console.print(f"\nRoger that! Exiting.", style="bold red")
            sys.exit()
        self.remote_host = self.get_host_ip_addr(target)
        try:
            input("\nPScan is ready. Press ENTER to run the scanner.")
        except KeyboardInterrupt:
            console.print(f"\nRoger that. Exiting.", style="bold red")
            sys.exit()
        else:
            self.run()

    def run(self):
        threadpool_executer(
            self.scan_port, self.ports_info.keys(), len(self.ports_info.keys())
        )
        self.show_completion_message()

if __name__ == "__main__":
    pscan = PScan()
    pscan.initialize()
