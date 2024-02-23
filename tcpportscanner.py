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
        self.remote_hosts = []

    def get_ports_info(self):
        data = extract_json_data(PScan.PORTS_DATA_FILE)
        self.ports_info = {int(k): v for (k, v) in data.items()}

    def scan_port(self, target, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        conn_status = sock.connect_ex((target, port))
        if conn_status == 0:
            if port in self.ports_info:
                service = self.ports_info[port]
            else:
                service = "Unknown"
            # Check if the connection is secure
            is_secure = self.check_secure_connection(target, port)
            self.open_ports.append((target, port, service, is_secure))
        sock.close()

    def check_secure_connection(self, target, port):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((target, port)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    return True
        except (ssl.CertificateError, ssl.SSLError, ConnectionRefusedError):
            return False

    def show_completion_message(self):
        print()
        if self.open_ports:
            console.print("Scan Completed. Open Ports:", style="bold blue")
            table = Table(show_header=True, header_style="bold green")
            table.add_column("IP", style="blue")
            table.add_column("PORT", style="blue")
            table.add_column("STATE", style="blue", justify="center")
            table.add_column("SERVICE", style="blue")
            table.add_column("SECURE", style="blue")
            table.add_column("SAFE TO CONNECT", style="blue")
            for entry in self.open_ports:
                target, port, service, is_secure = entry
                state = "OPEN"
                secure_status = "YES" if is_secure else "NO"
                safe_to_connect = "YES" if is_secure else "NO"
                table.add_row(target, str(port), state, service, secure_status, safe_to_connect)
            console.print(table)
        else:
            console.print(f"No Open Ports Found on Any Target", style="bold magenta")

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

    def get_host_ip_addrs(self, targets):
        ip_addrs = []
        for target in targets:
            try:
                ip_addr = socket.gethostbyname(target)
                console.print(f"\nIP address acquired for {target}: [bold blue]{ip_addr}[/bold blue]")
                ip_addrs.append(ip_addr)
            except socket.gaierror as e:
                console.print(f"{e} for {target}. Skipping.", style="bold red")
        return ip_addrs

    def initialize(self):
        self.show_startup_message()
        self.get_ports_info()
        try:
            targets_input = console.input("[bold blue]Enter comma-separated targets (IP addresses or hostnames): ").split(',')
            targets = [t.strip() for t in targets_input]
        except KeyboardInterrupt:
            console.print(f"\nRoger that! Exiting.", style="bold red")
            sys.exit()
        self.remote_hosts = self.get_host_ip_addrs(targets)
        if not self.remote_hosts:
            console.print(f"No valid targets provided. Exiting.", style="bold red")
            sys.exit()
        try:
            input("\nPScan is ready. Press ENTER to run the scanner.")
        except KeyboardInterrupt:
            console.print(f"\nRoger that. Exiting.", style="bold red")
            sys.exit()
        else:
            self.run()

    def run(self):
        for target in self.remote_hosts:
            threadpool_executer(
                self.scan_port, [(target, port) for port in self.ports_info.keys()], len(self.ports_info.keys())
            )
        self.show_completion_message()

if __name__ == "__main__":
    pscan = PScan()
    pscan.initialize()
