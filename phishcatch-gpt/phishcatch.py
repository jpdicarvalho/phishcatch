import argparse
import tldextract
import dns.resolver
import concurrent.futures
import csv
import requests
import whois
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init
from typing import List, Dict, Optional, Set

init(autoreset=True)

class PhishCatch:
    """
    PhishCatch is a Threat Intelligence tool designed to detect typosquatting
    and homograph attacks against a target domain.
    """
    
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.extracted = tldextract.extract(target_domain)
        self.base_name = self.extracted.domain
        self.suffix = self.extracted.suffix
        self.results: List[Dict] = []

    def generate_permutations(self) -> List[str]:
        """Generates domain permutations based on omission, repetition, transposition, and homoglyphs."""
        permutations: Set[str] = set()
        
        # 1. Omission
        for i in range(len(self.base_name)):
            permutations.add(f"{self.base_name[:i]}{self.base_name[i+1:]}.{self.suffix}")

        # 2. Repetition
        for i in range(len(self.base_name)):
            permutations.add(f"{self.base_name[:i]}{self.base_name[i]}{self.base_name[i:]}.{self.suffix}")
            
        # 3. Transposition
        for i in range(len(self.base_name) - 1):
            transposed = self.base_name[:i] + self.base_name[i+1] + self.base_name[i] + self.base_name[i+2:]
            permutations.add(f"{transposed}.{self.suffix}")
            
        # 4. Basic Homoglyphs
        homoglyphs = self.base_name.translate(str.maketrans('oli', '011'))
        if homoglyphs != self.base_name:
            permutations.add(f"{homoglyphs}.{self.suffix}")

        # Filter out empty, original, and invalid starting domains
        valid_perms = [
            d for d in permutations 
            if d and d != self.target_domain and not d.startswith('.')
        ]
        return valid_perms

    def check_http_status(self, domain: str) -> bool:
        """Checks if a domain has an active HTTP server."""
        try:
            response = requests.get(f"http://{domain}", timeout=3)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def check_domain_age(self, domain: str) -> Optional[int]:
        """Queries WHOIS to calculate the domain age in days."""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                days_old = (datetime.now() - creation_date).days
                return days_old
        except Exception:
            pass
        return None

    def check_mx_record(self, domain: str) -> bool:
        """Checks if a domain has configured MX records."""
        try:
            dns.resolver.resolve(domain, 'MX', lifetime=2)
            return True
        except Exception:
            return False

    def resolve_dns(self, domain: str) -> Dict:
        """Resolves DNS and performs threat intelligence checks for a given domain."""
        result = {
            "domain": domain,
            "is_registered": False,
            "ip_address": None,
            "has_mx_record": False,
            "has_website": False,
            "age_days": "Unknown",
            "threat_level": "LOW"
        }
        
        try:
            # Check A record to confirm registration
            answers = dns.resolver.resolve(domain, 'A', lifetime=2)
            result["is_registered"] = True
            result["ip_address"] = answers[0].to_text()

            # Threat checks
            result["has_mx_record"] = self.check_mx_record(domain)
            result["has_website"] = self.check_http_status(domain)
            
            age = self.check_domain_age(domain)
            if age is not None:
                result["age_days"] = age
            
            # Risk Scoring
            if result["has_mx_record"] and result["has_website"]:
                result["threat_level"] = "CRITICAL"
            elif result["has_mx_record"]:
                result["threat_level"] = "HIGH"
            elif result["has_website"]:
                result["threat_level"] = "MEDIUM"
                
            # Age penalty
            if age is not None and age < 30:
                if result["threat_level"] in ["LOW", "MEDIUM"]:
                    result["threat_level"] = "HIGH"
                elif result["threat_level"] == "HIGH":
                    result["threat_level"] = "CRITICAL"

        except Exception:
            # Domain not registered or DNS timeout
            pass 

        return result

    def scan(self) -> None:
        """Executes the concurrent scanning of generated permutations."""
        print(f"\n{Fore.CYAN}[*] Iniciando PhishCatch no alvo: {Fore.WHITE}{self.target_domain}{Style.RESET_ALL}")
        domains_to_test = self.generate_permutations()
        print(f"[*] {len(domains_to_test)} permutações de ameaça geradas.")
        print(f"[*] A resolver DNS, sondar servidores web e verificar Idade (WHOIS)...\n")

        scanned_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(self.resolve_dns, domain): domain for domain in domains_to_test}
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(domains_to_test), 
                               desc="Verificando", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)):
                scanned_results.append(future.result())

        self.results = [res for res in scanned_results if res["is_registered"]]

    def report(self) -> None:
        """Outputs the scan results to the terminal and exports them to a CSV file."""
        print(f"\n\n{Fore.GREEN}[+] Varredura Concluída! {len(self.results)} domínios maliciosos detetados.{Style.RESET_ALL}\n")
        
        if not self.results:
            print("Nenhuma ameaça imediata detetada.")
            return

        csv_file = f"phishcatch_report_gpt.csv"
        with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=["domain", "is_registered", "ip_address", "has_mx_record", "has_website", "age_days", "threat_level"])
            writer.writeheader()
            
            for res in self.results:
                writer.writerow(res)
                
                color = Fore.RED if res["threat_level"] in ["HIGH", "CRITICAL"] else Fore.YELLOW
                mx_str = "Sim" if res["has_mx_record"] else "Não"
                web_str = "Sim" if res["has_website"] else "Não"
                age_str = f"{res['age_days']} dias" if isinstance(res['age_days'], int) else res['age_days']
                
                print(f"{color}[!] {res['domain']:<15} | Idade: {age_str:<10} | E-mail: {mx_str:<3} | Site: {web_str:<3} | Risco: {res['threat_level']}{Style.RESET_ALL}")
                
        print(f"\n{Fore.CYAN}[*] Relatório de Inteligência exportado para: {csv_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishCatch - Threat Intelligence Typosquatting Scanner")
    parser.add_argument("domain", help="O domínio alvo para proteger (ex: empresa.com)")
    args = parser.parse_args()

    scanner = PhishCatch(args.domain)
    scanner.scan()
    scanner.report()
