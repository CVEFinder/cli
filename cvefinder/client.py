"""
CVEFinder API Client (async with aiohttp)
"""

import aiohttp
import asyncio
import time
import re
import json
from typing import Dict, Any, Optional
from urllib.parse import urlencode


class CVEFinderClient:
    """Client for CVEFinder.io API"""

    def __init__(self, api_key: str, verbose: bool = False):
        self.api_key = api_key
        self.api_url = 'https://cvefinder.io/api'
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'CVEFinder-CLI/1.0.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        if api_key:
            self.headers['Authorization'] = f'Bearer {api_key}'
        self._session: Optional[aiohttp.ClientSession] = None

    @staticmethod
    def _build_severity_counts(cves) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for cve in cves or []:
            sev = (cve.get('severity') or '').lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session (reuse for performance)"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(headers=self.headers)
        return self._session

    async def _close_session(self):
        """Close the aiohttp session"""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make async API request"""
        endpoint_path = f"/{endpoint.lstrip('/')}"
        url = f"{self.api_url}{endpoint_path}"

        start = time.time()
        if self.verbose:
            print(f"[DEBUG] {method} request")

        try:
            session_start = time.time()
            session = await self._get_session()
            if self.verbose:
                print(f"[DEBUG] Session ready in {time.time() - session_start:.3f}s")

            request_start = time.time()
            async with session.request(method, url, **kwargs) as response:
                if self.verbose:
                    print(f"[DEBUG] Response received in {time.time() - request_start:.3f}s (status: {response.status})")

                if response.status == 401:
                    raise Exception("Invalid API key. Please check your configuration.")
                elif response.status == 403:
                    raise Exception("Forbidden. This feature requires a Pro subscription.")
                elif response.status == 429:
                    raise Exception("Rate limit exceeded. Please try again later.")
                elif response.status >= 400:
                    error_msg = None
                    try:
                        error_data = await response.json()
                        if isinstance(error_data, dict):
                            error_msg = error_data.get('error') or error_data.get('message')
                    except Exception:
                        error_msg = None
                    if error_msg:
                        raise Exception(str(error_msg))
                    if response.status == 404:
                        raise Exception("Not Found")
                    else:
                        raise Exception(f"HTTP {response.status}: {response.reason}")

                json_start = time.time()
                result = await response.json()
                if self.verbose:
                    print(f"[DEBUG] JSON parsed in {time.time() - json_start:.3f}s")
                    print(f"[DEBUG] Total request time: {time.time() - start:.3f}s")

                return result
        except aiohttp.ClientError as e:
            raise Exception(f"Network error: {str(e)}")

    async def _run_with_cleanup(self, coro):
        """Run async coroutine and cleanup session"""
        start = time.time()
        try:
            if self.verbose:
                print(f"[DEBUG] Starting async operation...")
            result = await coro
            if self.verbose:
                print(f"[DEBUG] Operation completed in {time.time() - start:.3f}s")
            return result
        finally:
            cleanup_start = time.time()
            await self._close_session()
            if self.verbose:
                print(f"[DEBUG] Session cleanup took {time.time() - cleanup_start:.3f}s")
                print(f"[DEBUG] Total time with cleanup: {time.time() - start:.3f}s")

    def scan(self, url: str) -> Dict[str, Any]:
        """Initiate a scan"""
        return asyncio.run(self._run_with_cleanup(
            self._request('POST', '/scan', json={'target': url})
        ))

    def scan_and_get(self, url: str, max_wait: int = 120, poll_interval: float = 1.0) -> Dict[str, Any]:
        """
        Initiate a scan and wait for completion in one async run/session.
        This avoids the overhead of separate event loop/session setup for scan + get_scan.
        """
        return asyncio.run(self._run_with_cleanup(
            self._scan_and_get_async(url, max_wait=max_wait, poll_interval=poll_interval)
        ))

    def get_scan(self, scan_id: str, max_wait: int = 60, poll: bool = True) -> Dict[str, Any]:
        """Get scan results (with optional polling)"""
        return asyncio.run(self._run_with_cleanup(
            self._get_scan_async(scan_id, max_wait, poll)
        ))

    def get_scan_dependencies(self, scan_id: str) -> Dict[str, Any]:
        """Get dependency analysis for a scan."""
        return asyncio.run(self._run_with_cleanup(
            self._request('GET', f'/scan-dependencies?scan_id={scan_id}')
        ))

    async def _download_export(self, endpoint: str) -> Dict[str, Any]:
        """Download export content (JSON or PDF) and return bytes + metadata."""
        endpoint_path = f"/{endpoint.lstrip('/')}"
        url = f"{self.api_url}{endpoint_path}"
        if self.verbose:
            print("[DEBUG] GET export request")

        session = await self._get_session()
        try:
            async with session.request('GET', url) as response:
                content_type = (response.headers.get('Content-Type') or '').lower()
                content_disposition = response.headers.get('Content-Disposition') or ''

                filename = None
                match = re.search(r'filename=\"?([^\";]+)\"?', content_disposition, flags=re.IGNORECASE)
                if match:
                    filename = match.group(1).strip()

                if response.status in (401, 403, 404, 429) or response.status >= 400:
                    error_msg = None
                    try:
                        error_data = await response.json()
                        if isinstance(error_data, dict):
                            error_msg = error_data.get('error') or error_data.get('message')
                    except Exception:
                        error_msg = None
                    if error_msg:
                        raise Exception(str(error_msg))
                    raise Exception(f"HTTP {response.status}: {response.reason}")

                if 'application/json' in content_type:
                    data = await response.json()
                    # Some endpoints may return JSON errors with 200 status.
                    if isinstance(data, dict) and data.get('success') is False and data.get('error'):
                        raise Exception(str(data.get('error')))
                    return {
                        'success': True,
                        'content': json.dumps(data, indent=2).encode('utf-8'),
                        'content_type': 'application/json',
                        'filename': filename
                    }

                content = await response.read()
                return {
                    'success': True,
                    'content': content,
                    'content_type': content_type or 'application/octet-stream',
                    'filename': filename
                }
        except aiohttp.ClientError as e:
            raise Exception(f"Network error: {str(e)}")

    def export_scan_json(self, scan_id: int) -> Dict[str, Any]:
        """Export scan as JSON file content."""
        return asyncio.run(self._run_with_cleanup(
            self._download_export(f'/export-scan-json?id={int(scan_id)}')
        ))

    def export_scan_pdf(self, scan_id: int) -> Dict[str, Any]:
        """Export scan as PDF file content."""
        return asyncio.run(self._run_with_cleanup(
            self._download_export(f'/export-scan-pdf?id={int(scan_id)}')
        ))

    async def _scan_and_get_async(self, url: str, max_wait: int, poll_interval: float) -> Dict[str, Any]:
        """Async version of scan_and_get"""
        scan_result = await self._request('POST', '/scan', json={'target': url})
        if not scan_result.get('success'):
            raise Exception(scan_result.get('error', 'Scan failed'))

        scan_id = scan_result.get('scan_id')
        if not scan_id:
            raise Exception('Scan response missing scan_id')

        result = await self._get_scan_async(scan_id, max_wait=max_wait, poll=True, poll_interval=poll_interval)
        result['scan_id'] = scan_id
        return result

    async def _get_scan_async(self, scan_id: str, max_wait: int, poll: bool, poll_interval: float = 1.0) -> Dict[str, Any]:
        """Async version of get_scan"""
        start_time = time.time()
        poll_count = 0

        while True:
            poll_count += 1
            if self.verbose:
                print(f"[DEBUG] Poll attempt #{poll_count} (elapsed: {time.time() - start_time:.1f}s)")

            result = await self._request('GET', f'/get-scan?id={scan_id}')

            if result.get('success'):
                # API returns {"success": true, "scan": {...}, "technologies": [...], "cves": [...]}
                scan_data = result.get('scan', {})
                status = scan_data.get('status')

                if self.verbose:
                    print(f"[DEBUG] Scan status: {status}")

                if status == 'completed':
                    if self.verbose:
                        print(f"[DEBUG] Scan completed after {poll_count} polls in {time.time() - start_time:.1f}s")

                    # Return normalized response with success flag and data
                    technologies = result.get('technologies', [])
                    cves = result.get('cves', [])

                    # Build CVE count map by product
                    counts = {}
                    for cve in cves:
                        name = (cve.get('product_name') or cve.get('product') or '').lower()
                        if name:
                            counts[name] = counts.get(name, 0) + 1

                    # attach counts to technologies
                    for tech in technologies:
                        tech_name = (tech.get('technology') or tech.get('name') or '').lower()
                        tech['cve_count'] = counts.get(tech_name, 0)

                    severity_counts = self._build_severity_counts(cves)
                    return {
                        'success': True,
                        'data': {
                            **scan_data,
                            'technologies': technologies,
                            'cves': cves,
                            'total_cves': len(cves),
                            'severity_counts': severity_counts
                        }
                    }
                elif status == 'failed':
                    raise Exception(f"Scan failed: {scan_data.get('error', 'Unknown error')}")
                elif status in ['pending', 'processing', 'running']:
                    # If not polling, return immediately with status
                    if not poll:
                        cves = result.get('cves', []) or []
                        return {
                            'success': True,
                            'data': {
                                **scan_data,
                                'technologies': result.get('technologies', []),
                                'cves': cves,
                                'total_cves': len(cves),
                                'severity_counts': self._build_severity_counts(cves)
                            }
                        }

                    # Still processing, wait and retry
                    if time.time() - start_time > max_wait:
                        raise Exception(f"Scan timed out after {max_wait} seconds")

                    if self.verbose:
                        print(f"[DEBUG] Waiting {poll_interval:.1f}s before next poll...")
                    await asyncio.sleep(poll_interval)
                    continue
                else:
                    # Unknown status, return what we have
                    cves = result.get('cves', []) or []
                    return {
                        'success': True,
                        'data': {
                            **scan_data,
                            'technologies': result.get('technologies', []),
                            'cves': cves,
                            'total_cves': len(cves),
                            'severity_counts': self._build_severity_counts(cves)
                        }
                    }
            else:
                raise Exception(result.get('error', 'Failed to get scan results'))

    def list_scans(self, limit: int = 10, page: int = 1) -> Dict[str, Any]:
        """List recent scans"""
        return asyncio.run(self._run_with_cleanup(
            self._list_scans_async(limit=limit, page=page)
        ))

    async def _list_scans_async(self, limit: int = 10, page: int = 1) -> Dict[str, Any]:
        """Async version of list_scans using account-recent-scans endpoint."""
        # Backend supports per_page in [5, 50]. Normalize while preserving caller intent.
        requested = max(1, int(limit))
        per_page = max(5, min(50, requested))
        requested_page = max(1, int(page))

        result = await self._request('GET', f'/account-recent-scans?per_page={per_page}&page={requested_page}')

        if not result.get('success'):
            return result

        scans = result.get('scans', [])
        # Respect exact requested limit even if backend minimum per_page is 5.
        result['scans'] = scans[:requested]
        return result

    def list_public_scans(self, limit: int = 10, page: int = 1) -> Dict[str, Any]:
        """List recent public completed scans."""
        return asyncio.run(self._run_with_cleanup(
            self._request('GET', f'/recent-scans?per_page={max(1, min(limit, 10))}&page={max(1, page)}')
        ))

    def create_api_key(self, name: str) -> Dict[str, Any]:
        """Create new API key"""
        return asyncio.run(self._run_with_cleanup(
            self._request('POST', '/create-api-key', json={'name': name})
        ))

    def list_api_keys(self) -> Dict[str, Any]:
        """List all API keys"""
        return asyncio.run(self._run_with_cleanup(
            self._request('GET', '/list-api-keys')
        ))

    def revoke_api_key(self, key_id: int) -> Dict[str, Any]:
        """Revoke an API key"""
        return asyncio.run(self._run_with_cleanup(
            self._request('POST', '/revoke-api-key', json={'api_key_id': key_id})
        ))

    def rotate_api_key(self, key_id: int) -> Dict[str, Any]:
        """Rotate an API key"""
        return asyncio.run(self._run_with_cleanup(
            self._request('POST', '/rotate-api-key', json={'api_key_id': key_id})
        ))

    def get_account(self) -> Dict[str, Any]:
        """Get account information"""
        return asyncio.run(self._run_with_cleanup(
            self._request('GET', '/account-data')
        ))

    def search(
        self,
        query: str = '',
        severity: Optional[str] = None,
        published_year: Optional[int] = None,
        sort_by: Optional[str] = None,
        sort_order: Optional[str] = None,
        per_page: Optional[int] = None,
        page_cves: Optional[int] = None,
        page_products: Optional[int] = None,
        page_vendors: Optional[int] = None,
        cvss_min: Optional[float] = None,
        cvss_max: Optional[float] = None,
        epss_min: Optional[float] = None,
        epss_max: Optional[float] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        last_modified_after: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Search CVEs, products, and vendors."""
        params = {'q': query or ''}

        optional_params = {
            'severity': severity,
            'published_year': published_year,
            'sort_by': sort_by,
            'sort_order': sort_order,
            'per_page': per_page,
            'page_cves': page_cves,
            'page_products': page_products,
            'page_vendors': page_vendors,
            'cvss_min': cvss_min,
            'cvss_max': cvss_max,
            'epss_min': epss_min,
            'epss_max': epss_max,
            'date_from': date_from,
            'date_to': date_to,
            'last_modified_after': last_modified_after,
        }

        for key, value in optional_params.items():
            if value is not None and value != '':
                params[key] = value

        query_string = urlencode(params)
        return asyncio.run(self._run_with_cleanup(
            self._request('GET', f'/search?{query_string}')
        ))

    def toggle_monitoring(self, scan_id: int, action: str, frequency: str = 'weekly') -> Dict[str, Any]:
        """Enable or disable monitoring for a scan."""
        return asyncio.run(self._run_with_cleanup(
            self._request('POST', '/toggle-monitoring', json={
                'scan_id': int(scan_id),
                'action': action,
                'frequency': frequency
            })
        ))

    def get_exploits(self, cve_id: str) -> Dict[str, Any]:
        """Get exploit information for a CVE."""
        return asyncio.run(self._run_with_cleanup(
            self._request('GET', f'/get-exploits?cve_id={cve_id}')
        ))

    def get_exploits_by_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Get exploit information for a CVE ID (e.g. CVE-2021-24176).
        Backend currently expects internal numeric CVE ID, so resolve it from the CVE page when needed.
        """
        normalized = cve_id.strip().upper()
        if not normalized.startswith('CVE-'):
            normalized = f"CVE-{normalized}"

        # Try direct first in case backend accepts CVE string in future.
        try:
            return self.get_exploits(normalized)
        except Exception as e:
            if "Not Found" not in str(e) and "CVE not found" not in str(e):
                raise

        # Fallback: resolve internal numeric CVE ID from /cve/<CVE-ID> page.
        internal_id = asyncio.run(self._run_with_cleanup(
            self._resolve_cve_internal_id(normalized)
        ))
        if not internal_id:
            raise Exception(f"CVE not found: {normalized}")

        return self.get_exploits(str(internal_id))

    def bulk_scan(self, urls_text: str) -> Dict[str, Any]:
        """Start a bulk scan for multiple URLs."""
        return asyncio.run(self._run_with_cleanup(
            self._request('POST', '/bulk-scan', json={'urls': urls_text})
        ))

    def get_bulk_scan(self, bulk_scan_id: int, max_wait: int = 600, poll: bool = False, poll_interval: float = 3.0) -> Dict[str, Any]:
        """Get bulk scan status/results (with optional polling)."""
        return asyncio.run(self._run_with_cleanup(
            self._get_bulk_scan_async(bulk_scan_id, max_wait=max_wait, poll=poll, poll_interval=poll_interval)
        ))

    def list_bulk_scans(self, limit: int = 10, page: int = 1) -> Dict[str, Any]:
        """List recent bulk scans."""
        return asyncio.run(self._run_with_cleanup(
            self._list_bulk_scans_async(limit=limit, page=page)
        ))

    async def _get_bulk_scan_async(self, bulk_scan_id: int, max_wait: int, poll: bool, poll_interval: float = 3.0) -> Dict[str, Any]:
        """Async version of get_bulk_scan."""
        start_time = time.time()

        while True:
            result = await self._request('GET', f'/get-bulk-scan?id={int(bulk_scan_id)}')
            if not result.get('success'):
                raise Exception(result.get('error', 'Failed to get bulk scan results'))

            bulk = result.get('bulk_scan', {}) or {}
            status = (bulk.get('status') or '').lower()

            if not poll:
                return result

            if status in ('completed', 'failed'):
                return result

            if time.time() - start_time > max_wait:
                raise Exception(f"Bulk scan timed out after {max_wait} seconds")

            await asyncio.sleep(max(0.5, float(poll_interval)))

    async def _list_bulk_scans_async(self, limit: int = 10, page: int = 1) -> Dict[str, Any]:
        """Async version of list_bulk_scans using account-recent-bulk-scans endpoint."""
        requested = max(1, int(limit))
        per_page = max(5, min(10, requested))
        requested_page = max(1, int(page))

        result = await self._request(
            'GET',
            f'/account-recent-bulk-scans?per_page={per_page}&page={requested_page}'
        )
        if not result.get('success'):
            return result

        bulk_scans = result.get('bulk_scans', [])
        result['bulk_scans'] = bulk_scans[:requested]
        return result

    async def _resolve_cve_internal_id(self, cve_id: str) -> Optional[int]:
        """Resolve internal CVE DB id by parsing single CVE page script variable."""
        # /cve/<id> route is what the web app uses.
        page_url = f"https://cvefinder.io/cve/{cve_id}"
        session = await self._get_session()
        async with session.get(page_url) as response:
            if response.status >= 400:
                return None
            html = await response.text()

        # single_cve.php defines: const cveId = <int>;
        match = re.search(r"const\s+cveId\s*=\s*(\d+)\s*;", html)
        if not match:
            return None
        return int(match.group(1))
