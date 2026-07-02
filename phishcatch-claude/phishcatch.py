#!/usr/bin/env python3
"""
PhishCatch v2.0 — Automated Typosquatting & Homograph Threat Intelligence Tool

Academic cybersecurity artifact for proactive domain threat detection.
Generates domain permutations, resolves DNS, checks web/mail servers,
queries WHOIS age, and calculates risk levels using async concurrency.

Author: Academic Security Research
License: MIT
"""

import argparse
import asyncio
import csv
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import aiohttp
import dns.asyncresolver
import whois
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Data Model
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@dataclass
class DomainResult:
    """Stores the complete analysis results for a single domain permutation."""

    domain: str
    is_registered: bool = False
    ip_address: Optional[str] = None
    has_mx_record: bool = False
    has_website: bool = False
    age_days: Optional[int] = None
    threat_level: str = "LOW"

    def to_csv_dict(self) -> Dict[str, str]:
        """Convert to a dictionary suitable for CSV export."""
        return {
            "domain": self.domain,
            "is_registered": str(self.is_registered),
            "ip_address": self.ip_address or "",
            "has_mx_record": str(self.has_mx_record),
            "has_website": str(self.has_website),
            "age_days": str(self.age_days) if self.age_days is not None else "",
            "threat_level": self.threat_level,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Permutation Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class PermutationEngine:
    """Generates typosquatting and homograph domain permutations.

    Techniques implemented:
      - Omission:      Remove one character at a time.
      - Repetition:    Duplicate one character at a time.
      - Transposition: Swap each pair of adjacent characters.
      - Homographs:    Replace characters with visually similar substitutes.
    """

    HOMOGRAPH_MAP: Dict[str, List[str]] = {
        "a": ["4", "@"],
        "b": ["8"],
        "e": ["3"],
        "g": ["9"],
        "i": ["1", "!"],
        "l": ["1", "|"],
        "o": ["0"],
        "s": ["5", "$"],
        "t": ["7"],
    }

    def __init__(self, domain: str) -> None:
        """Parse the domain into name and TLD parts.

        Splits on the first dot so that compound TLDs are preserved.
        Example: 'google.com.br' -> name='google', tld='com.br'
        """
        if "." not in domain:
            raise ValueError(
                f"Domínio inválido: '{domain}'. Use o formato: exemplo.com"
            )

        dot_index = domain.index(".")
        self.name: str = domain[:dot_index]
        self.tld: str = domain[dot_index + 1 :]

    def _make_domain(self, name: str) -> str:
        """Reconstruct a full domain from a name variant and the original TLD."""
        return f"{name}.{self.tld}"

    def generate_all(self) -> List[str]:
        """Generate all permutation types and return a deduplicated, sorted list.

        The original domain is excluded from the results.
        """
        permutations: set = set()
        permutations.update(self.omission())
        permutations.update(self.repetition())
        permutations.update(self.transposition())
        permutations.update(self.homographs())

        # Remove the original domain and any invalid entries
        original = self._make_domain(self.name)
        permutations.discard(original)
        permutations = {
            d for d in permutations if d and not d.startswith(".")
        }

        return sorted(permutations)

    def omission(self) -> List[str]:
        """Generate permutations by removing one character at a time.

        Example: 'google' -> 'oogle', 'gogle', 'goole', 'googe', 'googl'
        """
        results: List[str] = []
        for i in range(len(self.name)):
            variant = self.name[:i] + self.name[i + 1 :]
            if variant:  # Skip if removing the only character
                results.append(self._make_domain(variant))
        return results

    def repetition(self) -> List[str]:
        """Generate permutations by duplicating one character at a time.

        Example: 'google' -> 'ggoogle', 'gooogle', 'googgle', ...
        """
        results: List[str] = []
        for i in range(len(self.name)):
            variant = self.name[:i] + self.name[i] * 2 + self.name[i + 1 :]
            results.append(self._make_domain(variant))
        return results

    def transposition(self) -> List[str]:
        """Generate permutations by swapping each pair of adjacent characters.

        Example: 'google' -> 'ogogle', 'goolge', 'googel', ...
        Identical swaps (e.g., swapping two 'o's) are automatically
        deduplicated when generate_all() converts results to a set.
        """
        results: List[str] = []
        for i in range(len(self.name) - 1):
            chars = list(self.name)
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            variant = "".join(chars)
            if variant != self.name:
                results.append(self._make_domain(variant))
        return results

    def homographs(self) -> List[str]:
        """Generate permutations by replacing characters with visual lookalikes.

        Each character is substituted individually (one at a time), producing
        all single-character homograph variants.
        Example: 'google' -> 'goo9le', 'g00gle', 'go0gle', ...
        """
        results: List[str] = []
        for i, char in enumerate(self.name):
            lower_char = char.lower()
            if lower_char in self.HOMOGRAPH_MAP:
                for replacement in self.HOMOGRAPH_MAP[lower_char]:
                    variant = self.name[:i] + replacement + self.name[i + 1 :]
                    results.append(self._make_domain(variant))
        return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Risk Assessor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class RiskAssessor:
    """Calculates threat level for a domain based on its infrastructure attributes.

    Risk matrix:
      - Web active + MX present = CRITICAL
      - MX present only         = HIGH
      - Web active only         = MEDIUM
      - Neither                 = LOW

    Age penalty:
      - Domains registered less than 30 days ago are escalated one level.
    """

    RISK_LEVELS: List[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    @classmethod
    def assess(
        cls, has_website: bool, has_mx_record: bool, age_days: Optional[int]
    ) -> str:
        """Determine the threat level based on infrastructure and domain age."""
        # Base risk from infrastructure
        if has_website and has_mx_record:
            level = "CRITICAL"
        elif has_mx_record:
            level = "HIGH"
        elif has_website:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Age penalty: escalate one level if domain is younger than 30 days
        if age_days is not None and age_days < 30:
            level = cls._escalate(level)

        return level

    @classmethod
    def _escalate(cls, current_level: str) -> str:
        """Escalate a risk level by one step. CRITICAL remains CRITICAL."""
        try:
            idx = cls.RISK_LEVELS.index(current_level)
            if idx < len(cls.RISK_LEVELS) - 1:
                return cls.RISK_LEVELS[idx + 1]
        except ValueError:
            pass
        return current_level


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Domain Analyzer (Async)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class DomainAnalyzer:
    """Performs asynchronous DNS, HTTP, MX, and WHOIS analysis on domains.

    Uses asyncio with a concurrency semaphore to efficiently analyze
    many domains in parallel without overwhelming the system.
    """

    def __init__(self, concurrency: int = 20, timeout: float = 3.0) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)

    async def analyze_domain(
        self, domain: str, session: aiohttp.ClientSession
    ) -> DomainResult:
        """Perform full analysis on a single domain permutation.

        Workflow:
          1. Resolve DNS A record — if it fails, the domain is not registered.
          2. In parallel: check MX records, HTTP status, and WHOIS age.
          3. Calculate the threat level from the gathered data.
        """
        result = DomainResult(domain=domain)

        async with self._semaphore:
            # Step 1: DNS A record resolution
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.lifetime = self.timeout
                answers = await resolver.resolve(domain, "A")
                result.is_registered = True
                result.ip_address = answers[0].to_text()
            except Exception:
                return result  # Not registered — skip further checks

            # Step 2: Parallel sub-checks for registered domains
            mx_task = self._check_mx(domain)
            http_task = self._check_http(domain, session)
            whois_task = self._check_whois(domain)

            mx_result, http_result, whois_result = await asyncio.gather(
                mx_task, http_task, whois_task, return_exceptions=True
            )

            result.has_mx_record = (
                mx_result if isinstance(mx_result, bool) else False
            )
            result.has_website = (
                http_result if isinstance(http_result, bool) else False
            )
            result.age_days = (
                whois_result
                if isinstance(whois_result, (int, type(None)))
                else None
            )

            # Step 3: Risk assessment
            result.threat_level = RiskAssessor.assess(
                result.has_website, result.has_mx_record, result.age_days
            )

        return result

    async def _check_mx(self, domain: str) -> bool:
        """Check if the domain has MX (mail exchange) records."""
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = self.timeout
            await resolver.resolve(domain, "MX")
            return True
        except Exception:
            return False

    async def _check_http(
        self, domain: str, session: aiohttp.ClientSession
    ) -> bool:
        """Check if the domain has an active web server returning HTTP 200."""
        try:
            async with session.get(
                f"http://{domain}",
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=True,
                ssl=False,
            ) as response:
                return response.status == 200
        except Exception:
            return False

    async def _check_whois(self, domain: str) -> Optional[int]:
        """Query WHOIS for domain creation date and return age in days.

        Runs in a thread executor since python-whois is synchronous.
        """
        try:
            loop = asyncio.get_running_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            creation_date = w.creation_date

            # WHOIS sometimes returns a list of dates; take the first
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date and isinstance(creation_date, datetime):
                return (datetime.now() - creation_date).days
        except Exception:
            pass
        return None

    async def analyze_all(
        self, domains: List[str], console: Console
    ) -> List[DomainResult]:
        """Analyze all domain permutations concurrently with a progress bar."""
        results: List[DomainResult] = []

        connector = aiohttp.TCPConnector(
            limit=self.concurrency, ssl=False
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[bold cyan]A analisar domínios...[/]"),
                BarColumn(
                    bar_width=40, style="cyan", complete_style="green"
                ),
                TaskProgressColumn(),
                TextColumn("•"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Análise", total=len(domains))

                tasks = [
                    self.analyze_domain(d, session) for d in domains
                ]

                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    progress.advance(task)

        return results


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Report Exporter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class ReportExporter:
    """Exports analysis results to CSV and displays them in the terminal."""

    CSV_COLUMNS: List[str] = [
        "domain",
        "is_registered",
        "ip_address",
        "has_mx_record",
        "has_website",
        "age_days",
        "threat_level",
    ]

    THREAT_COLORS: Dict[str, str] = {
        "CRITICAL": "bold red",
        "HIGH": "dark_orange",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    THREAT_ICONS: Dict[str, str] = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }

    @classmethod
    def display_results(
        cls, results: List[DomainResult], target: str, console: Console
    ) -> None:
        """Display results in a rich formatted table with a summary panel."""
        registered = [r for r in results if r.is_registered]

        if not registered:
            console.print(
                Panel(
                    "[green]✓ Nenhuma ameaça imediata detetada.[/green]",
                    title="Resultado",
                    border_style="green",
                )
            )
            return

        # ── Summary Panel ──
        critical = sum(1 for r in registered if r.threat_level == "CRITICAL")
        high = sum(1 for r in registered if r.threat_level == "HIGH")
        medium = sum(1 for r in registered if r.threat_level == "MEDIUM")
        low = sum(1 for r in registered if r.threat_level == "LOW")

        summary = Text()
        summary.append("  Alvo: ", style="bold")
        summary.append(f"{target}\n", style="bold cyan")
        summary.append("  Permutações testadas: ", style="bold")
        summary.append(f"{len(results)}\n", style="white")
        summary.append("  Domínios registados: ", style="bold")
        summary.append(f"{len(registered)}\n\n", style="bold yellow")
        summary.append(f"  🔴 CRITICAL: {critical}  ", style="bold red")
        summary.append(f"🟠 HIGH: {high}  ", style="dark_orange")
        summary.append(f"🟡 MEDIUM: {medium}  ", style="yellow")
        summary.append(f"🟢 LOW: {low}", style="green")

        console.print(
            Panel(
                summary,
                title="[bold]📊 Resumo da Análise de Ameaças[/bold]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        # ── Results Table ──
        table = Table(
            title="🎯 Domínios Suspeitos Detetados",
            box=box.ROUNDED,
            header_style="bold cyan",
            border_style="dim",
            show_lines=True,
            padding=(0, 1),
        )
        table.add_column("Domínio", style="bold white", min_width=22)
        table.add_column("IP", style="dim", min_width=15)
        table.add_column("Web", justify="center", min_width=5)
        table.add_column("MX", justify="center", min_width=5)
        table.add_column("Idade (dias)", justify="right", min_width=12)
        table.add_column("Risco", justify="center", min_width=10)

        # Sort by threat level severity (CRITICAL first)
        level_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        registered.sort(key=lambda r: level_order.get(r.threat_level, 4))

        for r in registered:
            color = cls.THREAT_COLORS.get(r.threat_level, "white")
            icon = cls.THREAT_ICONS.get(r.threat_level, "")
            age_str = str(r.age_days) if r.age_days is not None else "N/A"
            web_icon = "[green]✔[/green]" if r.has_website else "[dim]✘[/dim]"
            mx_icon = (
                "[green]✔[/green]" if r.has_mx_record else "[dim]✘[/dim]"
            )

            table.add_row(
                r.domain,
                r.ip_address or "N/A",
                web_icon,
                mx_icon,
                age_str,
                f"[{color}]{icon} {r.threat_level}[/{color}]",
            )

        console.print(table)

    @classmethod
    def export_csv(
        cls,
        results: List[DomainResult],
        target: str,
        output_dir: str,
        console: Console,
    ) -> Optional[str]:
        """Export all registered domain results to a CSV report file."""
        registered = [r for r in results if r.is_registered]
        if not registered:
            return None

        base_name = target.split(".")[0]
        filepath = Path(output_dir) / f"phishcatch_report_{base_name}.csv"

        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=cls.CSV_COLUMNS)
            writer.writeheader()
            for r in registered:
                writer.writerow(r.to_csv_dict())

        console.print(
            f"\n[bold cyan]📁 Relatório exportado para:[/bold cyan] "
            f"[underline]{filepath}[/underline]\n"
        )
        return str(filepath)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


BANNER = r"""
[bold cyan]
    ____  __    _      __   ______      __       __
   / __ \/ /_  (_)____/ /_ / ____/___ _/ /______/ /_
  / /_/ / __ \/ / ___/ __ \/ /   / __ `/ __/ ___/ __ \
 / ____/ / / / (__  ) / / / /___/ /_/ / /_/ /__/ / / /
/_/   /_/ /_/_/____/_/ /_/\____/\__,_/\__/\___/_/ /_/
[/bold cyan]
[dim]Automated Typosquatting & Homograph Threat Intelligence Tool[/dim]
[dim]v2.0 — Academic Cybersecurity Artifact[/dim]
"""


async def main() -> None:
    """Main async entry point for PhishCatch."""
    parser = argparse.ArgumentParser(
        description=(
            "PhishCatch v2.0 — Automated Typosquatting & Homograph "
            "Threat Intelligence Tool"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "domain",
        help="Domínio alvo a proteger (ex: google.com)",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=20,
        help="Número máximo de verificações concorrentes (default: 20)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=3.0,
        help="Timeout em segundos para cada verificação (default: 3.0)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=".",
        help="Diretoria de saída para o relatório CSV (default: .)",
    )

    args = parser.parse_args()
    console = Console()

    # ── Banner ──
    console.print(BANNER)

    # ── Validate domain ──
    if "." not in args.domain:
        console.print(
            "[bold red]✗ Erro:[/bold red] Domínio inválido. "
            "Use o formato: exemplo.com"
        )
        sys.exit(1)

    # ── Step 1: Generate permutations ──
    console.print(f"[bold cyan]🎯 Alvo:[/bold cyan] {args.domain}\n")

    engine = PermutationEngine(args.domain)
    permutations = engine.generate_all()

    console.print(
        f"[cyan]⚡ {len(permutations)} permutações geradas[/cyan] "
        f"(Omissão, Repetição, Transposição, Homógrafos)\n"
    )

    if not permutations:
        console.print(
            "[yellow]⚠ Nenhuma permutação gerada. "
            "Verifique o domínio introduzido.[/yellow]"
        )
        sys.exit(0)

    # ── Step 2: Analyze all domains concurrently ──
    analyzer = DomainAnalyzer(
        concurrency=args.concurrency, timeout=args.timeout
    )
    results = await analyzer.analyze_all(permutations, console)

    # ── Step 3: Display and export results ──
    console.print()
    ReportExporter.display_results(results, args.domain, console)
    ReportExporter.export_csv(results, args.domain, args.output, console)


if __name__ == "__main__":
    asyncio.run(main())
