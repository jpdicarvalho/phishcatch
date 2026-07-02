import argparse
import asyncio
import csv
import aiohttp
import aiodns
import whois
from datetime import datetime
import tldextract

class PhishCatchGLM:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        extracted = tldextract.extract(target_domain)
        self.domain = extracted.domain
        self.suffix = extracted.suffix
        self.resolver = aiodns.DNSResolver()
        self.results = []

    def get_permutations(self):
        perms = set()
        # Omission
        for i in range(len(self.domain)):
            perms.add(f"{self.domain[:i]}{self.domain[i+1:]}.{self.suffix}")
        # Repetition
        for i in range(len(self.domain)):
            perms.add(f"{self.domain[:i]}{self.domain[i]}{self.domain[i:]}.{self.suffix}")
        # Transposition
        for i in range(len(self.domain)-1):
            perms.add(f"{self.domain[:i]}{self.domain[i+1]}{self.domain[i]}{self.domain[i+2:]}.{self.suffix}")
        # Homoglyphs
        homo_map = {'o': '0', 'l': '1', 'i': '1', 'a': '4', 'e': '3'}
        for k, v in homo_map.items():
            if k in self.domain:
                perms.add(f"{self.domain.replace(k, v)}.{self.suffix}")
        
        return [p for p in perms if p != self.target_domain and len(p.split('.')[0]) > 0]

    async def check_domain(self, domain, session):
        result = {
            'domain': domain,
            'is_registered': False,
            'ip_address': '',
            'has_mx_record': False,
            'has_website': False,
            'age_days': 'N/A',
            'threat_level': 'LOW'
        }

        try:
            # Check A record
            answers = await self.resolver.query(domain, 'A')
            result['is_registered'] = True
            result['ip_address'] = answers[0].host
        except Exception:
            return result

        try:
            # Check MX record
            await self.resolver.query(domain, 'MX')
            result['has_mx_record'] = True
        except Exception:
            pass

        try:
            # Check HTTP
            async with session.get(f"http://{domain}", timeout=3) as resp:
                if resp.status == 200:
                    result['has_website'] = True
        except Exception:
            pass

        # Check WHOIS (Blocking call in thread to avoid blocking loop)
        try:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            cdate = w.creation_date
            if isinstance(cdate, list): cdate = cdate[0]
            if cdate:
                age = (datetime.now() - cdate).days
                result['age_days'] = age
        except Exception:
            pass

        # Threat calculation
        if result['has_website'] and result['has_mx_record']:
            result['threat_level'] = 'CRITICAL'
        elif result['has_mx_record']:
            result['threat_level'] = 'HIGH'
        elif result['has_website']:
            result['threat_level'] = 'MEDIUM'

        if isinstance(result['age_days'], int) and result['age_days'] < 30:
            if result['threat_level'] in ['LOW', 'MEDIUM']:
                result['threat_level'] = 'HIGH'
            elif result['threat_level'] == 'HIGH':
                result['threat_level'] = 'CRITICAL'

        return result

    async def run(self):
        perms = self.get_permutations()
        print(f"[*] Generated {len(perms)} permutations for {self.target_domain}")
        print("[*] Starting asynchronous scan...")
        
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_domain(p, session) for p in perms]
            results = await asyncio.gather(*tasks)
            self.results = [r for r in results if r['is_registered']]

    def save_report(self):
        if not self.results:
            print("No threats found.")
            return

        filename = "phishcatch_report_glm.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
            writer.writeheader()
            for r in self.results:
                writer.writerow(r)
                print(f"[!] Threat: {r['domain']} | IP: {r['ip_address']} | Level: {r['threat_level']}")
        
        print(f"[*] Report saved to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GLM PhishCatch Tool")
    parser.add_argument("domain", help="Target domain")
    args = parser.parse_args()

    scanner = PhishCatchGLM(args.domain)
    asyncio.run(scanner.run())
    scanner.save_report()
