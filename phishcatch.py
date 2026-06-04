import argparse
import tldextract
import dns.resolver
import concurrent.futures
import csv
from colorama import Fore, Style, init

# Inicializa as cores do terminal
init(autoreset=True)

class PhishCatch:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.extracted = tldextract.extract(target_domain)
        self.base_name = self.extracted.domain
        self.suffix = self.extracted.suffix
        self.results = []

    def generate_permutations(self):
        """Gera domínios falsos baseados em Typosquatting (omissão e repetição)"""
        permutations = set()
        
        # 1. Omission (Omissão de 1 letra) -> goog.com
        for i in range(len(self.base_name)):
            omission = self.base_name[:i] + self.base_name[i+1:]
            permutations.add(f"{omission}.{self.suffix}")

        # 2. Repetition (Repetição de 1 letra) -> goooogle.com
        for i in range(len(self.base_name)):
            repetition = self.base_name[:i] + self.base_name[i] + self.base_name[i:]
            permutations.add(f"{repetition}.{self.suffix}")
            
        # Filtra o próprio domínio original caso seja gerado acidentalmente
        return [domain for domain in permutations if domain != self.target_domain]

    def resolve_dns(self, domain):
        """Verifica se o domínio existe (Registo A) e se recebe emails (Registo MX)"""
        result = {
            "domain": domain,
            "is_registered": False,
            "ip_address": None,
            "has_mx_record": False,
            "threat_level": "LOW"
        }
        
        try:
            # Tenta resolver o endereço IP (Se resolver, o domínio está registado)
            answers = dns.resolver.resolve(domain, 'A', lifetime=2)
            result["is_registered"] = True
            result["ip_address"] = answers[0].to_text()

            # Se está registado, tenta ver se tem servidor de e-mail (Phishing BEC)
            try:
                dns.resolver.resolve(domain, 'MX', lifetime=2)
                result["has_mx_record"] = True
                result["threat_level"] = "HIGH" # Muito provável ser usado para phishing
            except Exception:
                result["threat_level"] = "MEDIUM" # Registado, mas sem e-mail ativo

        except Exception:
            pass # Domínio não existe (Livre para compra)

        return result

    def scan(self):
        print(f"{Fore.CYAN}[*] Iniciando PhishCatch no alvo: {self.target_domain}{Style.RESET_ALL}")
        domains_to_test = self.generate_permutations()
        print(f"[*] {len(domains_to_test)} variações de typosquatting geradas.")
        print(f"[*] Varrendo a internet (Resolução DNS multithread)...\n")

        # Usa multithreading para testar os domínios rapidamente
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            scanned_results = list(executor.map(self.resolve_dns, domains_to_test))

        # Filtra apenas os domínios que estão registados por alguém
        self.results = [res for res in scanned_results if res["is_registered"]]

    def report(self):
        print(f"\n{Fore.GREEN}[+] Varredura Concluída! {len(self.results)} domínios suspeitos encontrados.{Style.RESET_ALL}\n")
        
        if not self.results:
            print("Nenhuma ameaça imediata detetada.")
            return

        # Exporta para CSV
        csv_file = f"phishcatch_report_{self.base_name}.csv"
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["domain", "is_registered", "ip_address", "has_mx_record", "threat_level"])
            writer.writeheader()
            
            for res in self.results:
                writer.writerow(res)
                
                # Print no terminal com cores
                color = Fore.RED if res["threat_level"] == "HIGH" else Fore.YELLOW
                mx_status = "Sim (Phishing Alert!)" if res["has_mx_record"] else "Não"
                print(f"{color}[!] {res['domain']} | IP: {res['ip_address']} | Recebe E-mail: {mx_status}{Style.RESET_ALL}")
                
        print(f"\n{Fore.CYAN}[*] Relatório detalhado salvo em: {csv_file}{Style.RESET_ALL}")

# Configuração da Linha de Comandos
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishCatch - OSINT Typosquatting Analyzer")
    parser.add_argument("domain", help="O domínio alvo para proteger (ex: google.com)")
    args = parser.parse_args()

    scanner = PhishCatch(args.domain)
    scanner.scan()
    scanner.report()