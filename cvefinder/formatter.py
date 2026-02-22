"""
Output formatters for CVEFinder CLI
"""

import json
import csv
import io
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import Dict, Any, List


class Formatter:
    """Format scan results in different formats"""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.console = Console(force_terminal=False, legacy_windows=False)

    def to_json(self) -> str:
        """Format as JSON"""
        return json.dumps(self.data, indent=2)

    def to_csv(self) -> str:
        """Format CVEs as CSV"""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'CVE ID', 'Severity', 'CVSS Score', 'EPSS Score',
            'Published Date', 'Summary', 'Product', 'Version'
        ])

        # CVEs
        cves = self.data.get('cves', [])
        for cve in cves:
            product = cve.get('product_name') or cve.get('product', '')
            version = cve.get('detected_version') or cve.get('version', '')

            writer.writerow([
                cve.get('cve_id', ''),
                cve.get('severity', ''),
                cve.get('cvss_score', ''),
                cve.get('epss_score', ''),
                cve.get('published_date', ''),
                cve.get('summary', '')[:100],  # Truncate summary
                product,
                version
            ])

        return output.getvalue()

    def to_compact(self) -> str:
        """Format as compact text"""
        lines = []
        scan = self.data

        lines.append(f"URL: {scan.get('url')}")
        lines.append(f"Domain: {scan.get('domain')}")
        lines.append(f"Total CVEs: {scan.get('total_cves', 0)}")

        severity_counts = scan.get('severity_counts', {})
        lines.append(f"Critical: {severity_counts.get('critical', 0)}")
        lines.append(f"High: {severity_counts.get('high', 0)}")
        lines.append(f"Medium: {severity_counts.get('medium', 0)}")
        lines.append(f"Low: {severity_counts.get('low', 0)}")

        dep = scan.get('dependency_analysis') or {}
        if dep:
            lines.append("")
            lines.append("Dependency analysis:")
            lines.append(f"Status: {dep.get('status', 'N/A')}")
            lines.append(f"Total packages: {dep.get('total_packages', 0)}")
            lines.append(f"Vulnerable packages: {dep.get('vulnerable_packages', 0)}")
            lines.append(f"Internal packages: {dep.get('internal_packages', 0)}")
            if dep.get('requires_pro'):
                lines.append("Package details: requires Pro")
            else:
                lines.append(f"Remaining packages: {len(dep.get('remaining_list', []))}")

        return '\n'.join(lines)

    @staticmethod
    def _package_display_name(pkg: Dict[str, Any]) -> str:
        name = str(pkg.get('name', 'N/A'))
        version = str(pkg.get('version') or 'N/A')
        return f"{name} {version}"

    @staticmethod
    def _package_status(pkg: Dict[str, Any]) -> str:
        statuses = []
        if pkg.get('npm_available') == 0:
            statuses.append('internal')
        else:
            statuses.append('npm')
        vuln_count = len(pkg.get('vulnerabilities') or [])
        if vuln_count > 0:
            statuses.append('vulnerable')
        return ", ".join(statuses)

    def _render_dependency_table(self, title: str, packages: List[Dict[str, Any]]) -> str:
        table = Table(title=title, show_header=True, header_style="bold yellow")
        table.add_column("Package", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("CVEs", justify="right", style="red")

        for pkg in packages:
            vuln_count = len(pkg.get('vulnerabilities') or [])
            table.add_row(
                self._package_display_name(pkg),
                self._package_status(pkg),
                str(vuln_count)
            )

        with self.console.capture() as capture:
            self.console.print(table)
        return capture.get()

    def to_table(self) -> str:
        """Format as rich table"""
        scan = self.data

        # Summary Panel
        summary_text = f"""
[bold cyan]URL:[/bold cyan] {scan.get('url')}
[bold cyan]Domain:[/bold cyan] {scan.get('domain')}
[bold cyan]Status:[/bold cyan] {scan.get('status', 'N/A').upper()}
[bold cyan]Scanned:[/bold cyan] {scan.get('created_at', 'N/A')}

[bold]Total CVEs:[/bold] {scan.get('total_cves', 0)}
"""

        severity_counts = scan.get('severity_counts', {})
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        low = severity_counts.get('low', 0)

        if critical > 0:
            summary_text += f"\n🔴 [bold red]Critical:[/bold red] {critical}"
        if high > 0:
            summary_text += f"\n🟠 [bold yellow]High:[/bold yellow] {high}"
        if medium > 0:
            summary_text += f"\n🟡 [bold]Medium:[/bold] {medium}"
        if low > 0:
            summary_text += f"\n🔵 [bold cyan]Low:[/bold cyan] {low}"

        # Technologies
        technologies = scan.get('technologies', [])
        if technologies:
            summary_text += f"\n\n[bold]Technologies Detected:[/bold] {len(technologies)}"

        dep = scan.get('dependency_analysis') or {}
        if dep:
            summary_text += "\n\n[bold]Dependency Analysis:[/bold]"
            summary_text += f"\n[bold]Status:[/bold] {dep.get('status', 'N/A')}"
            summary_text += f"\n[bold]Total Packages:[/bold] {dep.get('total_packages', 0)}"
            summary_text += f"\n[bold]Vulnerable Packages:[/bold] {dep.get('vulnerable_packages', 0)}"
            summary_text += f"\n[bold]Internal Packages:[/bold] {dep.get('internal_packages', 0)}"
            if dep.get('requires_pro'):
                summary_text += "\n[dim]Package details require Pro[/dim]"

        # Create console for rendering
        console = self.console

        # Render summary
        with console.capture() as capture:
            console.print(Panel(summary_text.strip(), title="[bold]Scan Summary[/bold]", border_style="cyan"))

        output = capture.get()

        # CVEs Table
        cves = scan.get('cves', [])
        if cves:
            table = Table(title=f"\n{len(cves)} CVEs Found", show_header=True, header_style="bold magenta")

            table.add_column("CVE ID", style="cyan", no_wrap=True)
            table.add_column("Severity", style="yellow")
            table.add_column("CVSS", justify="right")
            table.add_column("EPSS %", justify="right")
            table.add_column("Product", style="green")
            table.add_column("Summary", style="dim", max_width=60)

            for cve in cves[:50]:  # Limit to 50 for readability
                severity = cve.get('severity', 'unknown').upper()

                # Color code severity
                if severity == 'CRITICAL':
                    severity_str = f"[bold red]{severity}[/bold red]"
                elif severity == 'HIGH':
                    severity_str = f"[bold yellow]{severity}[/bold yellow]"
                elif severity == 'MEDIUM':
                    severity_str = f"[bold]{severity}[/bold]"
                else:
                    severity_str = f"[cyan]{severity}[/cyan]"

                cvss = cve.get('cvss_score')
                cvss_str = f"{cvss:.1f}" if cvss is not None else "N/A"

                epss = cve.get('epss_score')
                epss_str = f"{epss:.1f}" if epss is not None else "N/A"

                summary = cve.get('summary', '')[:60]

                # Get product name and version
                product = cve.get('product_name') or cve.get('product', 'N/A')
                version = cve.get('detected_version')
                if version and version not in product:
                    product = f"{product} {version}"

                table.add_row(
                    cve.get('cve_id', 'N/A'),
                    severity_str,
                    cvss_str,
                    epss_str,
                    product,
                    summary
                )

            with console.capture() as capture:
                console.print(table)

            output += capture.get()

            if len(cves) > 50:
                output += f"\n[dim]... and {len(cves) - 50} more CVEs (use --format json to see all)[/dim]\n"

        # Technologies Table
        if technologies:
            tech_table = Table(title="\nDetected Technologies", show_header=True, header_style="bold green")
            tech_table.add_column("Name", style="green")
            tech_table.add_column("Version", style="cyan")
            tech_table.add_column("CVEs", justify="right", style="red")

            for tech in technologies:
                tech_table.add_row(
                    tech.get('technology', tech.get('name', 'N/A')),
                    tech.get('version') or 'N/A',
                    str(tech.get('cve_count', 0))
                )

            with console.capture() as capture:
                console.print(tech_table)

            output += capture.get()

        if dep and not dep.get('requires_pro'):
            vulnerable_list = dep.get('vulnerable_list', [])
            internal_list = dep.get('internal_list', [])
            remaining_list = dep.get('remaining_list', [])

            if vulnerable_list:
                output += self._render_dependency_table(
                    f"\nVulnerable Packages ({len(vulnerable_list)})",
                    vulnerable_list
                )
            if internal_list:
                output += self._render_dependency_table(
                    f"\nInternal Packages ({len(internal_list)})",
                    internal_list
                )

            if scan.get('dependency_full'):
                if remaining_list:
                    output += self._render_dependency_table(
                        f"\nRemaining Packages ({len(remaining_list)})",
                        remaining_list
                    )
            elif remaining_list:
                output += (
                    f"\n{len(remaining_list)} remaining packages hidden "
                    f"(use --full to show all dependency packages)\n"
                )

        return output
