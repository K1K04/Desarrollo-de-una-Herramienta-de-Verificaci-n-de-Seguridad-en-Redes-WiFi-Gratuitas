#!/usr/bin/env python3
# -- coding: utf-8 --

import socket
import ssl
import dns.resolver
import dns.exception
from datetime import datetime
import sys

class WiFiSecurityCheckerCLI:

    def __init__(self):

        self.sites_to_check = [
            "google.com",
            "facebook.com",
            "amazon.com",
            "cloudflare.com",
            "github.com",
            "microsoft.com",
            "ejemplo.com"
        ]

        self.trusted_dns_servers = [
            "8.8.8.8",        # Google
            "8.8.4.4",
            "1.1.1.1",        # Cloudflare
            "1.0.0.1",
            "9.9.9.9",        # Quad9
            "208.67.222.222", # OpenDNS
            "208.67.220.220"
        ]

    def print_header(self):
        print("\n" + "="*70)
        print("VERIFICADOR AVANZADO DE SEGURIDAD WIFI")
        print("Fecha:", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print("="*70 + "\n")

    def log(self, level, message):
        print(f"[{level}] {message}")

    # ---------------------------------------------------
    # DNS CHECK MEJORADO
    # ---------------------------------------------------
    def check_dns(self, domain):

        try:
            local_ips = set()
            for result in socket.getaddrinfo(domain, None):
                local_ips.add(result[4][0])

            print("  DNS Local:", list(local_ips))

            trusted_ips = set()

            for dns_server in self.trusted_dns_servers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    resolver.timeout = 3
                    resolver.lifetime = 3

                    answers = resolver.resolve(domain, 'A')
                    for rdata in answers:
                        trusted_ips.add(str(rdata))

                except dns.exception.DNSException:
                    continue

            if not trusted_ips:
                self.log("WARNING", "No se pudo verificar con DNS confiables")
                return True

            print("  DNS Confiables:", list(trusted_ips))

            if not local_ips.intersection(trusted_ips):
                self.log("ALERT", "Posible DNS spoofing detectado")
                return False

            self.log("OK", "DNS verificado correctamente")
            return True

        except Exception as e:
            self.log("ALERT", f"Error DNS: {e}")
            return False

    # ---------------------------------------------------
    # SSL CHECK MEJORADO
    # ---------------------------------------------------
    def check_ssl_certificate(self, domain):

        try:
            context = ssl.create_default_context()

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Validación oficial del hostname
                    ssl.match_hostname(cert, domain)

                    print("  Emisor:", cert.get('issuer'))
                    print("  Válido hasta:", cert.get('notAfter'))

                    self.log("OK", "Certificado SSL válido y verificado")
                    return True

        except ssl.CertificateError as e:
            self.log("ALERT", f"Certificado no coincide: {e}")
            return False

        except ssl.SSLError as e:
            self.log("ALERT", f"Error SSL: {e}")
            return False

        except Exception as e:
            self.log("WARNING", f"No se pudo verificar SSL: {e}")
            return True

    # ---------------------------------------------------
    def run_security_check(self):

        self.print_header()
        issues = 0

        for i, site in enumerate(self.sites_to_check, 1):

            print(f"\n[{i}/{len(self.sites_to_check)}] Verificando {site}")
            print("-" * 70)

            dns_safe = self.check_dns(site)
            ssl_safe = self.check_ssl_certificate(site)

            if not dns_safe or not ssl_safe:
                issues += 1
                self.log("WARNING", f"Problema detectado en {site}")
            else:
                self.log("OK", f"{site} parece seguro")

        print("\n" + "="*70)
        print("RESUMEN FINAL")
        print("="*70)

        if issues == 0:
            print("CONEXIÓN SEGURA")
        else:
            print(f"Se detectaron {issues} posibles problemas")
            print("Esta red podría ser peligrosa")

        print("\nVerificación completada:", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print("="*70 + "\n")

        return issues == 0


def main():
    try:
        checker = WiFiSecurityCheckerCLI()
        result = checker.run_security_check()
        sys.exit(0 if result else 1)

    except KeyboardInterrupt:
        print("\nVerificación cancelada por el usuario.\n")
        sys.exit(130)

    except Exception as e:
        print("\nError fatal:", str(e), "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

