import socket
import sys
import ssl
import pyfiglet
from rich.console import Console
from rich.table import Table
from utils import extract_json_data, threadpool_executer

console = Console()

class PScan:

    PORTS_DATA_FILE = "./COMMONPORTS.json" 
    SSL_CERT_FILE = "./server.crt" 
    SSL_KEY_FILE = "./server.key" 

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
            # Additional check for HTTP service
            if service.lower() == "http":
                if self.is_http_port_open(port):
                    self.open_ports.append((port, service, is_secure))
            else:
                self.open_ports.append((port, service, is_secure))
        sock.close()

    def check_secure_connection(self, port):
      context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
      context.check_hostname = True
      context.verify_mode = ssl.CERT_REQUIRED
      context.load_cert_chain(certfile=PScan.SSL_CERT_FILE, keyfile=PScan.SSL_KEY_FILE)
      try:
        with socket.create_connection((self.remote_host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=self.remote_host) as ssock:
                return "Connection is secure"
      except (ssl.CertificateError, ssl.SSLError, ConnectionRefusedError) as e:
        return f"Connection is not secure: {str(e)}"


    def is_http_port_open(self, port):
        http_get_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((self.remote_host, port))
                s.sendall(http_get_request)
                response = s.recv(1024)
                if b"HTTP/1.1" in response:
                    return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
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
            table.add_column("SAFE TO CONNECT", style="blue")
            for port_info in self.open_ports:
                port, service, is_secure = port_info
                state = "OPEN"
                secure_status = "YES" if is_secure else "NO"
                safe_to_connect = "YES" if is_secure else "NO"
                table.add_row(str(port), state, service, secure_status, safe_to_connect)
            console.print(table)
        else:
            console.print(f"No Open Ports Found on Target", style="bold magenta")

    @staticmethod
    def show_startup_message():
        ascii_art = pyfiglet.figlet_format(" PSCAN ")
        console.print(f"")

        console.print(
             "SIMPLE MULTITHREAD TCP PORT SCANNER "
        )

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
            targets = console.input("[bold blue]Targets (comma-separated): ").split(',')
        except KeyboardInterrupt:
            console.print(f"\nRoger that! Exiting.", style="bold red")
            sys.exit()
        for target in targets:
            target = target.strip()
            self.remote_host = self.get_host_ip_addr(target)
            try:
                input(f"\nPScan is ready for {target}. Press ENTER to run the scanner.")
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
