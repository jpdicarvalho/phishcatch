import argparse
import tldextract
import dns.resolver
import concurrent.futures
import csv
import requests
from tqdm import tqdm
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
        """Gera domínios falsos usando múltiplas técnicas de Typosquatting"""
        permutations = set()
        vowels = 'aeiou'
        
        # 1. Omission (Omissão)
        for i in range(len(self.base_name)):
            permutations.add(f"{self.base_name[:i]}{self.base_name[i+1:]}.{self.suffix}")

        # 2. Repetition (Repetição)
        for i in range(len(self.base_name)):
            permutations.add(f"{self.base_name[:i]}{self.base_name[i]}{self.base_name[i:]}.{self.suffix}")
            
        # 3. Transposition (Troca de letras adjacentes)
        for i in range(len(self.base_name) - 1):
            transposed = self.base_name[:i] + self.base_name[i+1] + self.base_name[i] + self.base_name[i+2:]
            permutations.add(f"{transposed}.{self.suffix}")
            
        # 4. Homoglyphs Básicos (o -> 0, l -> 1)
        homoglyphs = self.base_name.replace('o', '0').replace('l', '1').replace('i', '1')
        if homoglyphs != self.base_name:
            permutations.add(f"{homoglyphs}.{self.suffix}")

        return [domain for domain in permutations if domain and domain != self.target_domain and not domain.startswith('.')]

    def check_http_status(self, domain):
        """Tenta fazer um pedido HTTP para ver se existe um website ativo"""
        try:
            # Pedido rápido com timeout curto para não travar o script
            response = requests.get(f"http://{domain}", timeout=2)
            return True if response.status_code == 200 else False
        except requests.exceptions.RequestException:
            return False

    def resolve_dns(self, domain):
        """Verifica IP, Registo MX e Status HTTP"""
        result = {
            "domain": domain,
            "is_registered": False,
            "ip_address": None,
            "has_mx_record": False,
            "has_website": False,
            "threat_level": "LOW"
        }
        
        try:
            answers = dns.resolver.resolve(domain, 'A', lifetime=2)
            result["is_registered"] = True
            result["ip_address"] = answers[0].to_text()

            # Verifica e-mail ativo (MX)
            try:
                dns.resolver.resolve(domain, 'MX', lifetime=2)
                result["has_mx_record"] = True
            except Exception:
                pass
                
            # Verifica se o site abre no browser (HTTP 200)
            result["has_website"] = self.check_http_status(domain)
            
            # Cálculo de Risco
            if result["has_mx_record"] and result["has_website"]:
                result["threat_level"] = "CRITICAL"
            elif result["has_mx_record"]:
                result["threat_level"] = "HIGH"
            elif result["has_website"]:
                result["threat_level"] = "MEDIUM"

        except Exception:
            pass 

        return result

    def scan(self):
        print(f"\n{Fore.CYAN}[*] Iniciando PhishCatch no alvo: {Fore.WHITE}{self.target_domain}{Style.RESET_ALL}")
        domains_to_test = self.generate_permutations()
        print(f"[*] {len(domains_to_test)} permutações de ameaça geradas.")
        print(f"[*] A resolver DNS e sondar servidores web...\n")

        # Multithreading com Barra de Progresso visual (tqdm)
        scanned_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            # Mapeia as execuções e embrulha no tqdm para a barra animada
            futures = {executor.submit(self.resolve_dns, domain): domain for domain in domains_to_test}
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(domains_to_test), desc="Verificando", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Style.RESET_ALL)):
                scanned_results.append(future.result())

        self.results = [res for res in scanned_results if res["is_registered"]]

    def report(self):
        print(f"\n\n{Fore.GREEN}[+] Varredura Concluída! {len(self.results)} domínios maliciosos detetados.{Style.RESET_ALL}\n")
        
        if not self.results:
            print("Nenhuma ameaça imediata detetada.")
            return

        csv_file = f"phishcatch_report_{self.base_name}.csv"
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["domain", "is_registered", "ip_address", "has_mx_record", "has_website", "threat_level"])
            writer.writeheader()
            
            for res in self.results:
                writer.writerow(res)
                
                # Definição visual das cores por gravidade
                color = Fore.RED if res["threat_level"] in ["HIGH", "CRITICAL"] else Fore.YELLOW
                mx_str = "Sim" if res["has_mx_record"] else "Não"
                web_str = "Sim" if res["has_website"] else "Não"
                
                print(f"{color}[!] {res['domain']:<15} | IP: {res['ip_address']:<15} | E-mail MX: {mx_str:<3} | Site Web: {web_str:<3} | Risco: {res['threat_level']}{Style.RESET_ALL}")
                
        print(f"\n{Fore.CYAN}[*] Relatório de Inteligência exportado para: {csv_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishCatch - Threat Intelligence Typosquatting Scanner")
    parser.add_argument("domain", help="O domínio alvo para proteger (ex: empresa.com)")
    args = parser.parse_args()

    scanner = PhishCatch(args.domain)
    scanner.scan()
    scanner.report()