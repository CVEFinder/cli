#!/usr/bin/env python3
"""
CVEFinder CLI - Main entry point
"""

import click
import sys
import re
from rich.console import Console
from rich.table import Table

from .client import CVEFinderClient
from .config import Config
from .formatter import Formatter

console = Console()


def _parse_severity_filter(severity: str):
    """Parse and validate comma-separated severity filter values."""
    if not severity:
        return None

    allowed = {"critical", "high", "medium", "low"}
    values = {s.strip().lower() for s in severity.split(",") if s.strip()}
    invalid = sorted(values - allowed)

    if invalid:
        raise ValueError(f"Invalid severity value(s): {', '.join(invalid)}")

    return values or None


def _apply_severity_filter(data: dict, severities):
    """Filter CVEs in-place by severity and recompute summary counters."""
    if not severities:
        return

    cves = data.get("cves", [])
    filtered = [cve for cve in cves if (cve.get("severity") or "").lower() in severities]
    data["cves"] = filtered
    data["total_cves"] = len(filtered)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cve in filtered:
        sev = (cve.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
    data["severity_counts"] = counts


def _normalize_cve_id(value: str) -> str:
    """Normalize and validate CVE ID."""
    raw = (value or '').strip().upper()
    if not raw:
        raise ValueError("CVE ID is required")
    if not raw.startswith('CVE-'):
        raw = f"CVE-{raw}"
    if not re.match(r'^CVE-\d{4}-\d{4,}$', raw):
        raise ValueError("Invalid CVE ID format. Use e.g. CVE-2021-24176")
    return raw


def _build_monitor_candidates(client, mine_page: int = 1, public_page: int = 1, include_public: bool = True):
    """Build combined monitor candidate list from account scans and public scans."""
    candidates = []
    seen_ids = set()

    mine = client.list_scans(limit=10, page=max(1, mine_page))
    if mine.get('success'):
        for scan in mine.get('scans', []):
            scan_id = int(scan.get('id') or scan.get('scan_id') or 0)
            if not scan_id or scan_id in seen_ids:
                continue
            seen_ids.add(scan_id)
            candidates.append({
                'source': 'mine',
                'id': scan_id,
                'url': scan.get('url', 'N/A'),
                'domain': scan.get('domain', 'N/A'),
                'status': scan.get('status', 'N/A'),
                'tech_count': scan.get('tech_count', 0),
                'cve_count': scan.get('cve_count', scan.get('total_cves', 0)),
                'created_at': scan.get('created_at', 'N/A'),
            })

    if include_public:
        public = client.list_public_scans(limit=10, page=max(1, public_page))
        if public.get('success'):
            for scan in public.get('scans', []):
                scan_id = int(scan.get('id') or 0)
                if not scan_id or scan_id in seen_ids:
                    continue
                seen_ids.add(scan_id)
                candidates.append({
                    'source': 'public',
                    'id': scan_id,
                    'url': scan.get('url', 'N/A'),
                    'domain': scan.get('domain', 'N/A'),
                    'status': 'completed',
                    'tech_count': scan.get('tech_count', 0),
                    'cve_count': scan.get('cve_count', 0),
                    'created_at': scan.get('scanned_at', 'N/A'),
                })

    return candidates


def _prompt_select_scan(candidates, title="Select a scan"):
    """Prompt user to select a scan from candidates and return scan_id."""
    if not candidates:
        raise ValueError("No scans available to select from")

    table = Table(title=title)
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Source", style="yellow")
    table.add_column("Scan ID", style="cyan")
    table.add_column("URL", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Tech", style="magenta", justify="right")
    table.add_column("CVEs", style="red", justify="right")

    for idx, scan in enumerate(candidates, start=1):
        table.add_row(
            str(idx),
            scan.get('source', 'N/A'),
            str(scan.get('id', 'N/A')),
            str(scan.get('url', 'N/A')),
            str(scan.get('status', 'N/A')),
            str(scan.get('tech_count', 0)),
            str(scan.get('cve_count', 0)),
        )

    console.print()
    console.print(table)
    console.print()
    choice = click.prompt("Choose scan number", type=int)
    if choice < 1 or choice > len(candidates):
        raise ValueError("Invalid selection")
    return int(candidates[choice - 1]['id'])


def _interactive_select_scan(client, start_mine_page: int = 1, start_public_page: int = 1, include_public: bool = True):
    """Interactive paginated scan selector."""
    mine_page = max(1, start_mine_page)
    public_page = max(1, start_public_page)

    while True:
        candidates = _build_monitor_candidates(
            client,
            mine_page=mine_page,
            public_page=public_page,
            include_public=include_public
        )
        if not candidates:
            raise ValueError("No scans available to select from")

        table = Table(title=f"Select Scan To Monitor (my page {mine_page}, public page {public_page})")
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Source", style="yellow")
        table.add_column("Scan ID", style="cyan")
        table.add_column("URL", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Tech", style="magenta", justify="right")
        table.add_column("CVEs", style="red", justify="right")

        for idx, scan in enumerate(candidates, start=1):
            table.add_row(
                str(idx),
                scan.get('source', 'N/A'),
                str(scan.get('id', 'N/A')),
                str(scan.get('url', 'N/A')),
                str(scan.get('status', 'N/A')),
                str(scan.get('tech_count', 0)),
                str(scan.get('cve_count', 0)),
            )

        console.print()
        console.print(table)
        console.print("[dim]Select number, or type: n (next mine), p (prev mine), fn (next public), fp (prev public), q (cancel)[/dim]")
        raw = click.prompt("Choice", type=str).strip().lower()

        if raw.isdigit():
            choice = int(raw)
            if 1 <= choice <= len(candidates):
                return int(candidates[choice - 1]['id'])
            console.print("[red]Invalid selection number[/red]")
            continue

        if raw == 'n':
            mine_page += 1
            continue
        if raw == 'p':
            mine_page = max(1, mine_page - 1)
            continue
        if raw == 'fn':
            if include_public:
                public_page += 1
            else:
                console.print("[yellow]Public scans are disabled in this selector[/yellow]")
            continue
        if raw == 'fp':
            if include_public:
                public_page = max(1, public_page - 1)
            else:
                console.print("[yellow]Public scans are disabled in this selector[/yellow]")
            continue
        if raw == 'q':
            raise ValueError("Selection cancelled")

        console.print("[red]Invalid choice[/red]")


def _get_monitored_scans(client):
    """Fetch monitored scans list from account-data."""
    account = client.get_account()
    if not account.get('success'):
        raise Exception(account.get('error', 'Failed to fetch account data'))
    return account.get('monitored_scans', [])


def _read_bulk_urls(urls, input_file):
    """Read URLs from repeated --url options plus optional file/stdin."""
    candidates = []

    for url in urls or []:
        value = str(url).strip()
        if value:
            candidates.append(value)

    if input_file:
        if input_file == '-':
            content = sys.stdin.read()
        else:
            with open(input_file, 'r') as f:
                content = f.read()
        for line in content.splitlines():
            value = line.strip()
            if value:
                candidates.append(value)

    unique = []
    seen = set()
    for value in candidates:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(value)
    return unique


def _render_bulk_output(result, format):
    """Render bulk scan result in json/table/compact formats."""
    if format == 'json':
        import json
        return json.dumps(result, indent=2)

    bulk = result.get('bulk_scan')
    scans = result.get('scans', [])

    if format == 'compact':
        if not bulk:
            return (
                f"bulk_scan_id:{result.get('bulk_scan_id', 'N/A')} "
                f"total_urls:{result.get('total_urls', 0)} "
                f"scans_created:{result.get('scans_created', 0)} "
                f"failed:{result.get('failed', 0)}"
            )

        lines = [
            f"bulk_scan_id:{bulk.get('id', 'N/A')} status:{bulk.get('status', 'N/A')}",
            (
                f"progress:{bulk.get('progress_percentage', 0)}% "
                f"completed:{bulk.get('completed_scans', 0)} "
                f"pending:{bulk.get('pending_scans', 0)} "
                f"failed:{bulk.get('failed_scans', 0)} "
                f"total:{bulk.get('total_urls', 0)}"
            ),
        ]
        for scan in scans:
            lines.append(
                f"scan:{scan.get('id', 'N/A')} status:{scan.get('status', 'N/A')} "
                f"cves:{scan.get('cve_count', 0)} tech:{scan.get('tech_count', 0)} "
                f"url:{scan.get('url', 'N/A')}"
            )
        return "\n".join(lines)

    from rich.console import Console as RichConsole
    render_console = RichConsole(force_terminal=False, legacy_windows=False)

    if not bulk:
        table = Table(title="Bulk Scan Started")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Bulk Scan ID", str(result.get('bulk_scan_id', 'N/A')))
        table.add_row("Total URLs", str(result.get('total_urls', 0)))
        table.add_row("Scans Created", str(result.get('scans_created', 0)))
        table.add_row("Failed", str(result.get('failed', 0)))
        table.add_row("URL", str(result.get('url', 'N/A')))
        with render_console.capture() as capture:
            render_console.print(table)
        return capture.get()

    summary = Table(title=f"Bulk Scan #{bulk.get('id', 'N/A')}")
    summary.add_column("Field", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Status", str(bulk.get('status', 'N/A')))
    summary.add_row("Progress", f"{bulk.get('progress_percentage', 0)}%")
    summary.add_row("Total URLs", str(bulk.get('total_urls', 0)))
    summary.add_row("Completed", str(bulk.get('completed_scans', 0)))
    summary.add_row("Pending", str(bulk.get('pending_scans', 0)))
    summary.add_row("Failed", str(bulk.get('failed_scans', 0)))
    summary.add_row("Created At", str(bulk.get('created_at', 'N/A')))
    summary.add_row("Updated At", str(bulk.get('updated_at', 'N/A')))

    with render_console.capture() as capture:
        render_console.print(summary)
    output_text = capture.get()

    if scans:
        scan_table = Table(title=f"\nScans ({len(scans)})")
        scan_table.add_column("Scan ID", style="cyan")
        scan_table.add_column("Status", style="yellow")
        scan_table.add_column("Tech", justify="right", style="magenta")
        scan_table.add_column("CVEs", justify="right", style="red")
        scan_table.add_column("URL", style="green")
        for scan in scans:
            scan_table.add_row(
                str(scan.get('id', 'N/A')),
                str(scan.get('status', 'N/A')),
                str(scan.get('tech_count', 0)),
                str(scan.get('cve_count', 0)),
                str(scan.get('url', 'N/A')),
            )
        with render_console.capture() as capture:
            render_console.print(scan_table)
        output_text += capture.get()

    return output_text


@click.group()
@click.option('--api-key', help='API key for this command only (does not save)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode (errors only)')
@click.version_option(version='1.0.0')
@click.pass_context
def cli(ctx, api_key, verbose, quiet):
    """CVEFinder CLI - Scan websites for CVEs, vulnerabilities, and dependency analysis"""
    ctx.ensure_object(dict)

    # Load configuration
    config = Config()
    selected_profile = config.get_default_profile() or 'default'
    # Base profile data from config/env (do not mutate this object)
    profile_config = config.get_profile(selected_profile)
    runtime_config = dict(profile_config)

    # Command-line overrides are ephemeral for this invocation only
    if api_key:
        runtime_config['api_key'] = api_key

    # Store in context
    ctx.obj['config'] = runtime_config
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    ctx.obj['client'] = CVEFinderClient(
        api_key=runtime_config.get('api_key'),
        verbose=verbose
    )


@cli.command()
@click.option('--api-key', help='Your CVEFinder.io API key')
@click.option('--show', is_flag=True, help='Show current configuration')
@click.pass_context
def configure(ctx, api_key, show):
    """Configure CVEFinder CLI"""
    config = Config()
    profile = config.get_default_profile() or 'default'

    if show:
        current_config = config.get_profile(profile)
        console.print(f"\n[bold cyan]Configuration:[/bold cyan]")
        console.print(f"API Key: {current_config.get('api_key', 'Not set')}")
        console.print()
        return

    if not api_key:
        api_key = click.prompt('API Key', hide_input=False).strip()

    # Save configuration
    config.set_profile(profile, {
        'api_key': api_key
    })
    config.save()

    console.print(f"\n[green]✓[/green] Configuration saved")
    console.print(f"API Key: {api_key[:20]}...")
    console.print()


@cli.group(name='scan')
def scan_group():
    """Scan operations"""
    pass


@scan_group.command(name='run')
@click.argument('url')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'csv', 'compact']), default='table', help='Output format')
@click.option('--severity', help='Filter by severity (comma-separated: critical,high,medium,low)')
@click.pass_context
def scan_run(ctx, url, output, format, severity):
    """Scan a website for CVEs and vulnerabilities"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']
    quiet = ctx.obj['quiet']

    if not quiet:
        console.print(f"\n[cyan]Scanning:[/cyan] {url}")
        console.print("[dim]This may take 15-30 seconds (fetching, analyzing, looking up CVEs)...[/dim]\n")

    try:
        severity_filter = _parse_severity_filter(severity)

        # Get scan results with progress indicator
        if not quiet:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Scanning and analyzing...", total=None)
                scan_data = client.scan_and_get(url, max_wait=120)
        else:
            scan_data = client.scan_and_get(url, max_wait=120)

        if not scan_data.get('success'):
            console.print(f"[red]✗[/red] {scan_data.get('error', 'Failed to get scan results')}")
            sys.exit(1)

        scan_id = scan_data.get('scan_id')
        if verbose and scan_id:
            console.print(f"[dim]Scan ID: {scan_id}[/dim]")

        if severity_filter:
            _apply_severity_filter(scan_data.setdefault('data', {}), severity_filter)

        # Format output
        formatter = Formatter(scan_data.get('data', {}))

        if format == 'json':
            output_text = formatter.to_json()
        elif format == 'csv':
            output_text = formatter.to_csv()
        elif format == 'compact':
            output_text = formatter.to_compact()
        else:  # table
            output_text = formatter.to_table()

        # Save or print
        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            # Use print() instead of console.print() to avoid terminal hang issues
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@scan_group.command(name='list')
@click.option('--limit', default=10, type=int, show_default=True, help='Number of scans to return')
@click.option('--page', default=1, type=int, show_default=True, help='Page number to fetch')
@click.option('--format', '-f', type=click.Choice(['json', 'table']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def scan_list(ctx, limit, page, format, output):
    """List recent scans"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    if limit < 1:
        console.print("[red]Error:[/red] --limit must be >= 1")
        sys.exit(1)
    if limit > 50:
        console.print("[red]Error:[/red] --limit cannot be greater than 50")
        sys.exit(1)
    if page < 1:
        console.print("[red]Error:[/red] --page must be >= 1")
        sys.exit(1)

    try:
        result = client.list_scans(limit=limit, page=page)

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to list scans')}")
            sys.exit(1)

        scans = result.get('scans', [])
        pagination = result.get('pagination', {})

        if format == 'json':
            import json
            output_text = json.dumps({
                'scans': scans,
                'pagination': pagination
            }, indent=2)
        else:
            current_page = pagination.get('current_page', page)
            total_pages = pagination.get('total_pages', '?')
            table = Table(title=f"Recent Scans ({len(scans)}) - Page {current_page}/{total_pages}")
            table.add_column("ID", style="cyan")
            table.add_column("URL", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Tech Count", justify="right", style="magenta")
            table.add_column("Total CVEs", justify="right", style="red")
            table.add_column("Created", style="dim")

            for scan in scans:
                table.add_row(
                    str(scan.get('id') or scan.get('scan_id') or 'N/A'),
                    scan.get('url', 'N/A'),
                    str(scan.get('status', 'N/A')),
                    str(scan.get('tech_count', 0)),
                    str(scan.get('total_cves', scan.get('cve_count', 0))),
                    scan.get('created_at', 'N/A'),
                )

            from rich.console import Console as RichConsole
            render_console = RichConsole(force_terminal=False, legacy_windows=False)
            with render_console.capture() as capture:
                render_console.print(table)
            output_text = capture.get()
            if pagination:
                output_text += (
                    f"\nPage {pagination.get('current_page', page)} of {pagination.get('total_pages', '?')} "
                    f"(total scans: {pagination.get('total_scans', 'N/A')})\n"
                )

        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command(name='account')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'compact']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def account(ctx, format, output):
    """Show account details and daily scan usage"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        result = client.get_account()

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to get account data')}")
            sys.exit(1)

        if format == 'json':
            import json
            output_text = json.dumps(result, indent=2)
        elif format == 'compact':
            user = result.get('user', {})
            limit_info = result.get('limit_info', {})
            lines = [
                f"Email: {user.get('email', 'N/A')}",
                f"Plan: {user.get('plan_tier', 'N/A')} ({user.get('plan_status', 'N/A')})",
                f"Daily scans done: {limit_info.get('used', 0)}",
                f"Daily scan limit: {limit_info.get('limit', 0)}",
                f"Daily scans remaining: {limit_info.get('remaining', 0)}",
                f"Active API keys: {result.get('api_keys_count', 0)}",
                f"Active scheduled scans: {result.get('scheduled_scans_count', 0)}",
                f"Monitored scans: {len(result.get('monitored_scans', []))}",
                f"Active CVE alerts: {len(result.get('cve_alerts', []))}",
            ]
            output_text = "\n".join(lines)
        else:
            user = result.get('user', {})
            limit_info = result.get('limit_info', {})

            table = Table(title="Account Details")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Email", str(user.get('email', 'N/A')))
            table.add_row("Plan", str(user.get('plan_tier', 'N/A')))
            table.add_row("Plan Status", str(user.get('plan_status', 'N/A')))
            table.add_row("Subscription Ends", str(user.get('subscription_ends_at') or 'N/A'))
            table.add_row("Daily Scans Done", str(limit_info.get('used', 0)))
            table.add_row("Daily Scan Limit", str(limit_info.get('limit', 0)))
            table.add_row("Daily Scans Remaining", str(limit_info.get('remaining', 0)))
            table.add_row("Active API Keys", str(result.get('api_keys_count', 0)))
            table.add_row("Active Scheduled Scans", str(result.get('scheduled_scans_count', 0)))
            table.add_row("Monitored Scans", str(len(result.get('monitored_scans', []))))
            table.add_row("Active CVE Alerts", str(len(result.get('cve_alerts', []))))

            from rich.console import Console as RichConsole
            render_console = RichConsole(force_terminal=False, legacy_windows=False)
            with render_console.capture() as capture:
                render_console.print(table)
            output_text = capture.get()

        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.group(name='monitor')
def monitor():
    """Manage monitored scans"""
    pass


@monitor.command(name='add')
@click.option('--scan-id', type=int, help='Scan ID to monitor')
@click.option('--page', default=1, type=int, show_default=True, help='Page of your scans for interactive selection')
@click.option('--public-page', default=1, type=int, show_default=True, help='Page of public scans for interactive selection')
@click.option('--no-public', is_flag=True, help='Do not include public scans in interactive selection')
@click.pass_context
def monitor_add(ctx, scan_id, page, public_page, no_public):
    """Add/enable monitoring for a scan"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        if page < 1 or public_page < 1:
            console.print("[red]Error:[/red] --page and --public-page must be >= 1")
            sys.exit(1)

        selected_scan_id = scan_id
        if not selected_scan_id:
            include_public = not no_public
            selected_scan_id = _interactive_select_scan(
                client,
                start_mine_page=page,
                start_public_page=public_page,
                include_public=include_public,
            )

        monitored_scans = _get_monitored_scans(client)
        existing = next((m for m in monitored_scans if int(m.get('scan_id', 0)) == int(selected_scan_id)), None)
        if existing and existing.get('is_active'):
            console.print(f"\n[yellow]ℹ[/yellow] Scan {selected_scan_id} is already actively monitored.\n")
            return

        frequency = 'weekly'
        result = client.toggle_monitoring(selected_scan_id, 'enable', frequency=frequency)
        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to add monitoring')}")
            sys.exit(1)

        monitoring = result.get('monitoring') or {}
        console.print(f"\n[green]✓[/green] Monitoring enabled for scan {selected_scan_id}")
        if monitoring:
            console.print(f"URL: {monitoring.get('url', 'N/A')}")
            console.print(f"Frequency: {monitoring.get('frequency', frequency)}")
            console.print(f"Next check: {monitoring.get('next_check_at', 'N/A')}\n")
        else:
            console.print()

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@monitor.command(name='check')
@click.option('--scan-id', type=int, required=True, help='Scan ID to check')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'compact']), default='table', help='Output format')
@click.pass_context
def monitor_check(ctx, scan_id, format):
    """Check monitoring status for a scan"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        monitored_scans = _get_monitored_scans(client)
        monitoring = next((m for m in monitored_scans if int(m.get('scan_id', 0)) == int(scan_id)), None)
        is_monitored = monitoring is not None

        if format == 'json':
            import json
            print(json.dumps({
                'success': True,
                'is_monitored': is_monitored,
                'monitoring': monitoring
            }, indent=2))
            return

        if format == 'compact':
            if not is_monitored:
                print(f"scan:{scan_id} monitored:no")
            else:
                status = "active" if monitoring.get('is_active') else "inactive"
                print(f"scan:{scan_id} monitored:yes status:{status} frequency:{monitoring.get('frequency', 'N/A')}")
            return

        table = Table(title=f"Monitoring Status: Scan {scan_id}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Monitored", "Yes" if is_monitored else "No")
        if is_monitored and monitoring:
            table.add_row("Monitor ID", str(monitoring.get('id', 'N/A')))
            table.add_row("Status", "Active" if monitoring.get('is_active') else "Inactive")
            table.add_row("Frequency", str(monitoring.get('frequency', 'N/A')))
            table.add_row("URL", str(monitoring.get('url', 'N/A')))
            table.add_row("Next Check", str(monitoring.get('next_check_at', 'N/A')))

        console.print()
        console.print(table)
        console.print()

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@monitor.command(name='list')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'compact']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def monitor_list(ctx, format, output):
    """List monitored scans"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        monitored_scans = _get_monitored_scans(client)

        if format == 'json':
            import json
            output_text = json.dumps(monitored_scans, indent=2)
        elif format == 'compact':
            if not monitored_scans:
                output_text = "No monitored scans found"
            else:
                lines = []
                for item in monitored_scans:
                    status = "active" if item.get('is_active') else "inactive"
                    lines.append(
                        f"#{item.get('id')} scan:{item.get('scan_id')} {status} {item.get('frequency')} {item.get('url', 'N/A')}"
                    )
                output_text = "\n".join(lines)
        else:
            table = Table(title=f"Monitored Scans ({len(monitored_scans)})")
            table.add_column("Monitor ID", style="cyan")
            table.add_column("Scan ID", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Frequency", style="green")
            table.add_column("URL", style="green")
            table.add_column("Next Check", style="dim")
            table.add_column("CVEs", justify="right", style="red")

            for item in monitored_scans:
                status = "✓ Active" if item.get('is_active') else "✗ Inactive"
                table.add_row(
                    str(item.get('id', 'N/A')),
                    str(item.get('scan_id', 'N/A')),
                    status,
                    str(item.get('frequency', 'N/A')),
                    str(item.get('url', 'N/A')),
                    str(item.get('next_check_at', 'N/A')),
                    str(item.get('last_cve_count', 0))
                )

            from rich.console import Console as RichConsole
            render_console = RichConsole(force_terminal=False, legacy_windows=False)
            with render_console.capture() as capture:
                render_console.print(table)
            output_text = capture.get()

        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@monitor.command(name='enable')
@click.option('--scan-id', type=int, help='Scan ID to enable monitoring for')
@click.option('--monitor-id', type=int, help='Existing monitor ID to enable')
@click.pass_context
def monitor_enable(ctx, scan_id, monitor_id):
    """Enable an existing monitored scan"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        monitored_scans = _get_monitored_scans(client)
        selected_scan_id = scan_id

        if monitor_id:
            match = next((m for m in monitored_scans if int(m.get('id', 0)) == int(monitor_id)), None)
            if not match:
                raise ValueError(f"Monitor ID {monitor_id} not found")
            selected_scan_id = int(match.get('scan_id'))
            selected_frequency = 'weekly'
        elif selected_scan_id:
            match = next((m for m in monitored_scans if int(m.get('scan_id', 0)) == int(selected_scan_id)), None)
            selected_frequency = 'weekly'
        else:
            if not monitored_scans:
                raise ValueError("No monitored scans found")
            candidates = [{
                'source': 'monitor',
                'id': int(item.get('scan_id')),
                'url': item.get('url', 'N/A'),
                'status': 'active' if item.get('is_active') else 'inactive',
                'tech_count': 0,
                'cve_count': item.get('last_cve_count', 0)
            } for item in monitored_scans]
            selected_scan_id = _prompt_select_scan(candidates, title="Select Monitored Scan To Enable")
            selected_frequency = 'weekly'

        result = client.toggle_monitoring(selected_scan_id, 'enable', frequency=selected_frequency)
        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to enable monitoring')}")
            sys.exit(1)

        console.print(f"\n[green]✓[/green] Monitoring enabled for scan {selected_scan_id}\n")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@monitor.command(name='disable')
@click.option('--scan-id', type=int, help='Scan ID to disable monitoring for')
@click.option('--monitor-id', type=int, help='Existing monitor ID to disable')
@click.pass_context
def monitor_disable(ctx, scan_id, monitor_id):
    """Disable an existing monitored scan"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        monitored_scans = _get_monitored_scans(client)
        selected_scan_id = scan_id

        if monitor_id:
            match = next((m for m in monitored_scans if int(m.get('id', 0)) == int(monitor_id)), None)
            if not match:
                raise ValueError(f"Monitor ID {monitor_id} not found")
            selected_scan_id = int(match.get('scan_id'))
        elif not selected_scan_id:
            if not monitored_scans:
                raise ValueError("No monitored scans found")
            candidates = [{
                'source': 'monitor',
                'id': int(item.get('scan_id')),
                'url': item.get('url', 'N/A'),
                'status': 'active' if item.get('is_active') else 'inactive',
                'tech_count': 0,
                'cve_count': item.get('last_cve_count', 0)
            } for item in monitored_scans]
            selected_scan_id = _prompt_select_scan(candidates, title="Select Monitored Scan To Disable")

        result = client.toggle_monitoring(selected_scan_id, 'disable', frequency='weekly')
        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to disable monitoring')}")
            sys.exit(1)

        console.print(f"\n[green]✓[/green] Monitoring disabled for scan {selected_scan_id}\n")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command(name='search')
@click.argument('query', required=False, default='')
@click.option('--severity', help='Comma-separated severity filter (critical,high,medium,low)')
@click.option('--published-year', type=int, help='Filter by published year')
@click.option('--sort-by', type=click.Choice(['cvss_score', 'epss_score', 'published_date', 'last_modified']), default='published_date', show_default=True, help='Sort field')
@click.option('--sort-order', type=click.Choice(['asc', 'desc']), default='desc', show_default=True, help='Sort order')
@click.option('--per-page', type=int, default=10, show_default=True, help='Results per section per page')
@click.option('--page-cves', type=int, default=1, show_default=True, help='CVE results page')
@click.option('--page-products', type=int, default=1, show_default=True, help='Product results page')
@click.option('--page-vendors', type=int, default=1, show_default=True, help='Vendor results page')
@click.option('--cvss-min', type=float, help='Minimum CVSS score (free/pro)')
@click.option('--cvss-max', type=float, help='Maximum CVSS score (free/pro)')
@click.option('--epss-min', type=float, help='Minimum EPSS score (free/pro)')
@click.option('--epss-max', type=float, help='Maximum EPSS score (free/pro)')
@click.option('--date-from', help='Published from date (YYYY-MM-DD, free/pro)')
@click.option('--date-to', help='Published to date (YYYY-MM-DD, free/pro)')
@click.option('--last-modified-after', help='Last modified after date (YYYY-MM-DD, free/pro)')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'compact']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def search_cmd(ctx, query, severity, published_year, sort_by, sort_order, per_page, page_cves, page_products, page_vendors,
               cvss_min, cvss_max, epss_min, epss_max, date_from, date_to, last_modified_after, format, output):
    """Search CVEs, products, and vendors"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    if per_page < 1:
        console.print("[red]Error:[/red] --per-page must be >= 1")
        sys.exit(1)
    if page_cves < 1 or page_products < 1 or page_vendors < 1:
        console.print("[red]Error:[/red] page values must be >= 1")
        sys.exit(1)

    try:
        result = client.search(
            query=query,
            severity=severity,
            published_year=published_year,
            sort_by=sort_by,
            sort_order=sort_order,
            per_page=per_page,
            page_cves=page_cves,
            page_products=page_products,
            page_vendors=page_vendors,
            cvss_min=cvss_min,
            cvss_max=cvss_max,
            epss_min=epss_min,
            epss_max=epss_max,
            date_from=date_from,
            date_to=date_to,
            last_modified_after=last_modified_after,
        )

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Search failed')}")
            sys.exit(1)

        if format == 'json':
            import json
            output_text = json.dumps(result, indent=2)
        elif format == 'compact':
            counts = result.get('counts', {})
            pagination = result.get('pagination', {})
            lines = [
                f"Query: {result.get('query', '')}",
                f"Tier: {result.get('user_tier', 'N/A')}",
                f"CVEs: {counts.get('cves', 0)} (page {pagination.get('cves', {}).get('page', 1)}/{pagination.get('cves', {}).get('total_pages', 0)})",
                f"Products: {counts.get('products', 0)} (page {pagination.get('products', {}).get('page', 1)}/{pagination.get('products', {}).get('total_pages', 0)})",
                f"Vendors: {counts.get('vendors', 0)} (page {pagination.get('vendors', {}).get('page', 1)}/{pagination.get('vendors', {}).get('total_pages', 0)})",
            ]
            output_text = "\n".join(lines)
        else:
            results = result.get('results', {})
            counts = result.get('counts', {})
            pagination = result.get('pagination', {})
            user_tier = result.get('user_tier', 'N/A')

            from rich.console import Console as RichConsole
            from rich.panel import Panel
            render_console = RichConsole(force_terminal=False, legacy_windows=False)

            with render_console.capture() as capture:
                render_console.print(Panel(
                    f"Query: {result.get('query', '')}\n"
                    f"Tier: {user_tier}\n"
                    f"Returned: CVEs={counts.get('cves', 0)}, Products={counts.get('products', 0)}, Vendors={counts.get('vendors', 0)}",
                    title="Search Summary",
                    border_style="cyan"
                ))
            output_text = capture.get()

            cves = results.get('cves', [])
            if cves:
                cve_table = Table(title=f"\nCVEs (total: {pagination.get('cves', {}).get('total', len(cves))})")
                cve_table.add_column("CVE ID", style="cyan")
                cve_table.add_column("Severity", style="yellow")
                cve_table.add_column("CVSS", justify="right")
                cve_table.add_column("EPSS", justify="right")
                cve_table.add_column("Published", style="dim")
                cve_table.add_column("Summary", style="dim", max_width=60)
                for cve in cves:
                    cvss = cve.get('cvss_score')
                    epss = cve.get('epss_score')
                    cve_table.add_row(
                        cve.get('cve_id', 'N/A'),
                        str(cve.get('severity', 'N/A')),
                        f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "N/A",
                        f"{epss:.1f}" if isinstance(epss, (int, float)) else "N/A",
                        str(cve.get('published_date', 'N/A')),
                        str(cve.get('summary', ''))[:60]
                    )
                with render_console.capture() as capture:
                    render_console.print(cve_table)
                output_text += capture.get()

            products = results.get('products', [])
            if products:
                product_table = Table(title=f"\nProducts (total: {pagination.get('products', {}).get('total', len(products))})")
                product_table.add_column("Product", style="green")
                product_table.add_column("Vendor", style="cyan")
                for product in products:
                    product_table.add_row(
                        str(product.get('name', 'N/A')),
                        str(product.get('vendor_name', 'N/A'))
                    )
                with render_console.capture() as capture:
                    render_console.print(product_table)
                output_text += capture.get()

            vendors = results.get('vendors', [])
            if vendors:
                vendor_table = Table(title=f"\nVendors (total: {pagination.get('vendors', {}).get('total', len(vendors))})")
                vendor_table.add_column("Vendor", style="yellow")
                for vendor in vendors:
                    vendor_table.add_row(str(vendor.get('name', 'N/A')))
                with render_console.capture() as capture:
                    render_console.print(vendor_table)
                output_text += capture.get()

            if not cves and not products and not vendors:
                output_text += "\nNo results found.\n"

        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command(name='exploit')
@click.argument('cve_id')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'compact']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def exploit_cmd(ctx, cve_id, format, output):
    """Get exploit information for a CVE"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        normalized = _normalize_cve_id(cve_id)
        result = client.get_exploits_by_cve(normalized)

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to get exploits')}")
            sys.exit(1)

        if format == 'json':
            import json
            output_text = json.dumps(result, indent=2)
        elif format == 'compact':
            lines = [
                f"CVE: {normalized}",
                f"Exploit count: {result.get('exploit_count', 0)}",
                f"Pro access: {'yes' if result.get('is_pro') else 'no'}",
            ]
            if not result.get('is_pro') and result.get('message'):
                lines.append(f"Message: {result.get('message')}")
            exploits = result.get('exploits', [])
            if exploits:
                lines.append("")
                lines.append("Entries:")
                for idx, exp in enumerate(exploits, start=1):
                    has_poc = bool(exp.get('exploit_code'))
                    source_url = exp.get('source_url') or ''
                    source_url_short = source_url[:70] + ('...' if len(source_url) > 70 else '')
                    code_preview = (exp.get('exploit_code') or '').strip().splitlines()
                    code_preview = code_preview[0][:80] if code_preview else ''
                    lines.append(
                        f"{idx}. {exp.get('exploit_id', 'N/A')} | {exp.get('source', 'N/A')} | "
                        f"poc:{'yes' if has_poc else 'no'} | verified:{'yes' if exp.get('verified') else 'no'}"
                    )
                    if source_url_short:
                        lines.append(f"   source: {source_url_short}")
                    if code_preview:
                        lines.append(f"   code: {code_preview}")
            output_text = "\n".join(lines)
        else:
            table = Table(title=f"Exploits: {normalized}")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("CVE", normalized)
            table.add_row("Exploit Count", str(result.get('exploit_count', 0)))
            table.add_row("Pro Access", "Yes" if result.get('is_pro') else "No")
            if not result.get('is_pro') and result.get('message'):
                table.add_row("Message", str(result.get('message')))

            from rich.console import Console as RichConsole
            render_console = RichConsole(force_terminal=False, legacy_windows=False)
            with render_console.capture() as capture:
                render_console.print(table)
            output_text = capture.get()

            exploits = result.get('exploits', [])
            if exploits:
                exp_table = Table(title=f"\nExploit Entries ({len(exploits)})")
                exp_table.add_column("#", style="cyan", justify="right")
                exp_table.add_column("Source", style="yellow")
                exp_table.add_column("Type", style="magenta")
                exp_table.add_column("PoC", style="blue")
                exp_table.add_column("Verified", style="green")
                exp_table.add_column("Published", style="dim")
                for idx, exp in enumerate(exploits, start=1):
                    has_poc = "Yes" if exp.get('exploit_code') else "No"
                    exp_table.add_row(
                        str(idx),
                        str(exp.get('source', 'N/A')),
                        str(exp.get('exploit_type', 'N/A')),
                        has_poc,
                        "Yes" if exp.get('verified') else "No",
                        str(exp.get('published_date', 'N/A'))
                    )
                with render_console.capture() as capture:
                    render_console.print(exp_table)
                output_text += capture.get()

                titles_table = Table(title="\nExploit Titles (full)")
                titles_table.add_column("#", style="cyan", justify="right")
                titles_table.add_column("Title", style="green", overflow="fold")
                for idx, exp in enumerate(exploits, start=1):
                    titles_table.add_row(str(idx), str(exp.get('title', 'N/A')))
                with render_console.capture() as capture:
                    render_console.print(titles_table)
                output_text += capture.get()

                urls_table = Table(title="\nExploit Source URLs (full)")
                urls_table.add_column("#", style="cyan", justify="right")
                urls_table.add_column("Source URL", style="dim", overflow="fold")
                for idx, exp in enumerate(exploits, start=1):
                    urls_table.add_row(str(idx), str(exp.get('source_url', 'N/A') or 'N/A'))
                with render_console.capture() as capture:
                    render_console.print(urls_table)
                output_text += capture.get()

                code_table = Table(title="\nExploit Code (full)")
                code_table.add_column("#", style="cyan", justify="right")
                code_table.add_column("Code", style="dim", overflow="fold")
                for idx, exp in enumerate(exploits, start=1):
                    code = str(exp.get('exploit_code', '') or '').strip()
                    code_table.add_row(str(idx), code if code else "N/A")
                with render_console.capture() as capture:
                    render_console.print(code_table)
                output_text += capture.get()

        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@scan_group.command(name='get')
@click.argument('scan_id')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'csv', 'compact']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.option('--wait', is_flag=True, help='Wait for scan to complete if still processing')
@click.option('--full', is_flag=True, help='Show full dependency package list (not only vulnerable/internal)')
@click.pass_context
def scan_get(ctx, scan_id, format, output, wait, full):
    """Get scan results by scan ID with dependency analysis summary"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        result = client.get_scan(scan_id, poll=wait)

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to get scan')}")
            sys.exit(1)

        # Check scan status
        data = result.get('data', {})
        status = data.get('status')

        if status in ['pending', 'processing']:
            console.print(f"\n[yellow]⏳[/yellow] Scan is still {status}")
            console.print(f"[dim]Try again in a few seconds or use --wait flag[/dim]\n")
            console.print(f"Command: [cyan]cvefinder scan get {scan_id} --wait[/cyan]\n")
            sys.exit(0)

        if status == 'failed':
            console.print(f"\n[red]✗[/red] Scan failed: {data.get('error', 'Unknown error')}\n")
            sys.exit(1)

        # Attach dependency analysis data if available.
        dependency_warning = None
        try:
            dependency_result = client.get_scan_dependencies(scan_id)
            if isinstance(dependency_result, dict) and not dependency_result.get('error'):
                packages = dependency_result.get('packages') or []

                vulnerable_packages = []
                internal_packages = []
                remaining_packages = []

                for pkg in packages:
                    vulnerabilities = pkg.get('vulnerabilities') or []
                    is_vulnerable = len(vulnerabilities) > 0
                    is_internal = pkg.get('npm_available') == 0

                    if is_vulnerable:
                        vulnerable_packages.append(pkg)
                    elif is_internal:
                        internal_packages.append(pkg)
                    else:
                        remaining_packages.append(pkg)

                data['dependency_analysis'] = {
                    'status': dependency_result.get('status', 'unknown'),
                    'total_packages': int(dependency_result.get('total_packages', 0) or 0),
                    'vulnerable_packages': int(dependency_result.get('vulnerable_packages', 0) or 0),
                    'internal_packages': int(dependency_result.get('internal_packages', 0) or 0),
                    'requires_pro': bool(dependency_result.get('requires_pro', False)),
                    'vulnerable_list': vulnerable_packages,
                    'internal_list': internal_packages,
                    'remaining_list': remaining_packages,
                }
                data['dependency_full'] = bool(full)
            elif isinstance(dependency_result, dict) and dependency_result.get('error'):
                dependency_warning = dependency_result.get('error')
        except Exception as dep_err:
            dependency_warning = str(dep_err)

        # Format output
        formatter = Formatter(data)

        if format == 'json':
            output_text = formatter.to_json()
        elif format == 'csv':
            output_text = formatter.to_csv()
        elif format == 'compact':
            output_text = formatter.to_compact()
        else:  # table
            output_text = formatter.to_table()

        # Save or print
        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            # Use print() instead of console.print() to avoid terminal hang issues
            print(output_text)

        if dependency_warning and format != 'json':
            console.print(f"[yellow]Dependency analysis warning:[/yellow] {dependency_warning}")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command(name='export')
@click.argument('scan_id', type=int)
@click.option('--json', 'as_json', is_flag=True, help='Export as JSON')
@click.option('--pdf', 'as_pdf', is_flag=True, help='Export as PDF')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def export_cmd(ctx, scan_id, as_json, as_pdf, output):
    """Export a scan report as JSON or PDF"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        if as_json == as_pdf:
            raise ValueError("Choose exactly one format flag: --json or --pdf")

        if as_json:
            result = client.export_scan_json(scan_id)
            ext = 'json'
        else:
            result = client.export_scan_pdf(scan_id)
            ext = 'pdf'

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Export failed')}")
            sys.exit(1)

        output_path = output or result.get('filename') or f"scan-{scan_id}.{ext}"
        content = result.get('content', b'')
        if not isinstance(content, (bytes, bytearray)):
            content = str(content).encode('utf-8')

        with open(output_path, 'wb') as f:
            f.write(content)

        console.print(f"\n[green]✓[/green] Export saved to {output_path}\n")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.group(name='bulk')
def bulk():
    """Bulk scan operations"""
    pass


@bulk.command(name='scan')
@click.option('--url', 'urls', multiple=True, help='URL to include (repeat for multiple URLs)')
@click.option('--input-file', '-i', help='File containing URLs (one per line), or "-" for stdin')
@click.option('--wait', is_flag=True, help='Wait for bulk scan completion')
@click.option('--max-wait', default=600, type=int, show_default=True, help='Max wait seconds when --wait is used')
@click.option('--interval', default=3.0, type=float, show_default=True, help='Polling interval in seconds when --wait is used')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'compact']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def bulk_scan_cmd(ctx, urls, input_file, wait, max_wait, interval, format, output):
    """Start a bulk scan for multiple URLs"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        if max_wait < 1:
            raise ValueError("--max-wait must be >= 1")
        if interval <= 0:
            raise ValueError("--interval must be > 0")

        url_list = _read_bulk_urls(urls, input_file)
        if len(url_list) < 2:
            raise ValueError("Provide at least 2 URLs via --url and/or --input-file")

        start_result = client.bulk_scan("\n".join(url_list))
        if not start_result.get('success'):
            console.print(f"[red]✗[/red] {start_result.get('error', 'Bulk scan failed')}")
            sys.exit(1)

        result = start_result
        if wait:
            bulk_scan_id = start_result.get('bulk_scan_id')
            if not bulk_scan_id:
                raise Exception("Bulk scan response missing bulk_scan_id")
            result = client.get_bulk_scan(
                int(bulk_scan_id),
                max_wait=max_wait,
                poll=True,
                poll_interval=interval
            )

        output_text = _render_bulk_output(result, format)

        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@bulk.command(name='get')
@click.argument('bulk_scan_id', type=int)
@click.option('--wait', is_flag=True, help='Wait until bulk scan reaches a final state')
@click.option('--max-wait', default=600, type=int, show_default=True, help='Max wait seconds when --wait is used')
@click.option('--interval', default=3.0, type=float, show_default=True, help='Polling interval in seconds when --wait is used')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'compact']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def bulk_get_cmd(ctx, bulk_scan_id, wait, max_wait, interval, format, output):
    """Get bulk scan status/results by bulk scan ID"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    try:
        if max_wait < 1:
            raise ValueError("--max-wait must be >= 1")
        if interval <= 0:
            raise ValueError("--interval must be > 0")

        result = client.get_bulk_scan(
            int(bulk_scan_id),
            max_wait=max_wait,
            poll=wait,
            poll_interval=interval
        )

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to get bulk scan')}")
            sys.exit(1)

        output_text = _render_bulk_output(result, format)

        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@bulk.command(name='list')
@click.option('--limit', default=10, type=int, show_default=True, help='Number of bulk scans to return')
@click.option('--page', default=1, type=int, show_default=True, help='Page number to fetch')
@click.option('--format', '-f', type=click.Choice(['json', 'table', 'compact']), default='table', help='Output format')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def bulk_list_cmd(ctx, limit, page, format, output):
    """List recent bulk scans"""
    client = ctx.obj['client']
    verbose = ctx.obj['verbose']

    if limit < 1:
        console.print("[red]Error:[/red] --limit must be >= 1")
        sys.exit(1)
    if limit > 10:
        console.print("[red]Error:[/red] --limit cannot be greater than 10")
        sys.exit(1)
    if page < 1:
        console.print("[red]Error:[/red] --page must be >= 1")
        sys.exit(1)

    try:
        result = client.list_bulk_scans(limit=limit, page=page)
        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to list bulk scans')}")
            sys.exit(1)

        bulk_scans = result.get('bulk_scans', [])
        pagination = result.get('pagination', {})

        if format == 'json':
            import json
            output_text = json.dumps({
                'bulk_scans': bulk_scans,
                'pagination': pagination
            }, indent=2)
        elif format == 'compact':
            lines = []
            for item in bulk_scans:
                total = int(item.get('total_urls', 0) or 0)
                completed = int(item.get('completed_scans', 0) or 0)
                failed = int(item.get('failed_scans', 0) or 0)
                pending = max(0, total - completed - failed)
                lines.append(
                    f"bulk:{item.get('id', 'N/A')} status:{item.get('status', 'N/A')} "
                    f"total:{total} completed:{completed} pending:{pending} failed:{failed}"
                )
            output_text = "\n".join(lines) if lines else "No bulk scans found"
        else:
            table = Table(title=f"Recent Bulk Scans ({len(bulk_scans)})")
            table.add_column("Bulk ID", style="cyan")
            table.add_column("Status", style="yellow")
            table.add_column("Total URLs", justify="right", style="magenta")
            table.add_column("Completed", justify="right", style="green")
            table.add_column("Pending", justify="right", style="blue")
            table.add_column("Failed", justify="right", style="red")
            table.add_column("Created", style="dim")

            for item in bulk_scans:
                total = int(item.get('total_urls', 0) or 0)
                completed = int(item.get('completed_scans', 0) or 0)
                failed = int(item.get('failed_scans', 0) or 0)
                pending = max(0, total - completed - failed)
                table.add_row(
                    str(item.get('id', 'N/A')),
                    str(item.get('status', 'N/A')),
                    str(total),
                    str(completed),
                    str(pending),
                    str(failed),
                    str(item.get('created_at', 'N/A'))
                )

            from rich.console import Console as RichConsole
            render_console = RichConsole(force_terminal=False, legacy_windows=False)
            with render_console.capture() as capture:
                render_console.print(table)
            output_text = capture.get()
            if pagination:
                output_text += (
                    f"\nPage {pagination.get('current_page', page)} of {pagination.get('total_pages', '?')} "
                    f"(total bulk scans: {pagination.get('total_bulk_scans', 'N/A')})\n"
                )

        if output:
            with open(output, 'w') as f:
                f.write(output_text)
            console.print(f"\n[green]✓[/green] Results saved to {output}")
        else:
            print(output_text)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.group(name='api-keys')
def api_keys():
    """Manage API keys"""
    pass


@api_keys.command(name='create')
@click.option('--name', prompt='Key name', help='Name for the API key')
@click.pass_context
def create_key(ctx, name):
    """Create a new API key"""
    client = ctx.obj['client']

    try:
        result = client.create_api_key(name)

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to create API key')}")
            sys.exit(1)

        console.print("\n[green]✓[/green] API key created successfully!")
        console.print(f"Key ID: {result.get('key_id')}")
        console.print(f"[bold yellow]API Key: {result.get('api_key')}[/bold yellow]")
        console.print("\n[dim]⚠️  Save this key securely - it won't be shown again![/dim]\n")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


@api_keys.command(name='list')
@click.pass_context
def list_keys(ctx):
    """List all API keys"""
    client = ctx.obj['client']

    try:
        result = client.list_api_keys()

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to list API keys')}")
            sys.exit(1)

        keys = result.get('keys', [])

        if not keys:
            console.print("\n[dim]No API keys found[/dim]\n")
            return

        table = Table(title="API Keys")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Created", style="dim")

        for key in keys:
            status = "✓ Active" if key.get('is_active') else "✗ Inactive"
            table.add_row(
                str(key.get('id')),
                key.get('name', 'N/A'),
                status,
                key.get('created_at', 'N/A')
            )

        console.print("\n")
        console.print(table)
        console.print("\n")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


@api_keys.command(name='revoke')
@click.argument('key_id', type=int)
@click.confirmation_option(prompt='Are you sure you want to revoke this API key?')
@click.pass_context
def revoke_key(ctx, key_id):
    """Revoke an API key"""
    client = ctx.obj['client']

    try:
        result = client.revoke_api_key(key_id)

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to revoke API key')}")
            sys.exit(1)

        console.print(f"\n[green]✓[/green] API key {key_id} revoked successfully\n")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


@api_keys.command(name='rotate')
@click.argument('key_id', type=int)
@click.pass_context
def rotate_key(ctx, key_id):
    """Rotate an API key"""
    client = ctx.obj['client']

    try:
        result = client.rotate_api_key(key_id)

        if not result.get('success'):
            console.print(f"[red]✗[/red] {result.get('error', 'Failed to rotate API key')}")
            sys.exit(1)

        new_key = result.get('new_key') or result.get('api_key')
        console.print("\n[green]✓[/green] API key rotated successfully!")
        console.print(f"[bold yellow]New API Key: {new_key}[/bold yellow]")
        console.print("\n[dim]⚠️  Update your applications with the new key![/dim]\n")

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


def main():
    """Main entry point"""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Fatal error:[/red] {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
