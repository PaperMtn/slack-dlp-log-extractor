"""
Slack DLP violations log extractor.

Fetches DLP violation alerts from Slack Enterprise by mimicking the admin UI request
flow and calling the (unofficial) `admin.dlp.violations.list` endpoint.

Authentication:
- Uses the Slack `d` cookie to load the enterprise admin page and extract an
  `xoxc-...` enterprise_api_token from the HTML.
- Both the cookie and token are sensitive secrets. Do not log them.

Caveats:
- This relies on Slack's UI/auth internals and may break without notice.

Output:
- Prints each violation as a single JSON object (NDJSON) to stdout.

Usage:
  python slack_dlp_extractor.py \
    --slack-cookie "$D_COOKIE" \
    --enterprise-domain "your-company.slack.com" \
    --earliest 1704067200 \
    --latest 1704153600 \

Timestamps:
- `earliest` and `latest` are epoch seconds and filter on `date_create`.
"""

import re
import os
import json
import argparse
import logging
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

LOG = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
DEFAULT_LIMIT = 100

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
)


class SlackClient:
    def __init__(self, d_cookie: str, enterprise_domain: str, timeout: int = DEFAULT_TIMEOUT) -> None:
        if not d_cookie:
            raise ValueError("d_cookie is required (set D_COOKIE).")
        if not enterprise_domain:
            raise ValueError("enterprise_domain is required (set ENTERPRISE_DOMAIN).")

        self.enterprise_domain = enterprise_domain.strip()
        self.base_url = f"https://{self.enterprise_domain}/api/"
        self.timeout = timeout

        self.session = requests.Session()
        self.session.cookies.set("d", d_cookie)
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })

        self._configure_retries()
        self.user_token = self._get_user_token()

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "SlackClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _configure_retries(self) -> None:
        retry = Retry(
            total=5,
            connect=5,
            read=5,
            status=5,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)

    def _get_user_token(self) -> str:
        response = self.session.get(
            f"https://{self.enterprise_domain}",
            timeout=self.timeout,
        )
        response.raise_for_status()

        # Find the user token with enterprise wide scope `"enterprise_api_token": "xoxc-..."` in the response
        match = re.search(r'enterprise_api_token"\s*:\s*"(xoxc-[^"]+)"', response.text)
        if not match:
            # Fallback: Try to find any `xoxc-` token in the response
            match = re.search(r"(xoxc-[A-Za-z0-9-]+)", response.text)

        if not match:
            raise ValueError(
                "Could not find enterprise_api_token (xoxc-...) in the response. "
                "Slack UI or auth flow may have changed."
            )
        return match.group(1)

    def get_dlp_violations(
            self,
            limit: int = DEFAULT_LIMIT,
            latest: Optional[int] = None,
            earliest: Optional[int] = None,
            violation_status: str = "0",
    ) -> list[dict[str, Any]]:
        """
        Retrieves DLP violation data from Slack by mimicking a browser request
        to the admin.dlp.violations.list endpoint.

        Notes:
        - This is an unofficial endpoint, it may break without notice.
        - earliest/latest should be epoch seconds.
        """
        url = f"{self.base_url}admin.dlp.violations.list"
        data: dict[str, str] = {
            "token": self.user_token,
            "limit": str(limit),
            "violation_status": violation_status,
            "_x_reason": "native-dlp-violations-table-list",
            "_x_mode": "online",
            "_x_app_name": "manage",
        }

        alerts: list[dict[str, Any]] = []
        cursor: str | None = None

        # Paginate through results
        while True:
            if cursor:
                data["cursor"] = cursor
            else:
                data.pop("cursor", None)

            response = self.session.post(url, data=data, timeout=30)
            response.raise_for_status()
            payload = response.json()

            if not payload.get("ok", False):
                error = payload.get("error") or "unknown_error"
                if error in {"invalid_auth", "not_authed", "account_inactive"}:
                    LOG.warning("Auth error from Slack (%s). Refreshing token and retrying once.", error)
                    self.user_token = self._get_user_token()
                    data["token"] = self.user_token

                    response = self.session.post(url, data=data, timeout=self.timeout)
                    response.raise_for_status()
                    payload = response.json()

                if not payload.get("ok", False):
                    raise ValueError(f"Error from Slack API: {payload.get('error')}")

            page_alerts = payload.get("violation_alerts", []) or []

            for alert in page_alerts:
                # Apply earliest/latest filtering
                date_create = int(alert.get("date_create", 0) or 0)
                if latest is not None and date_create > latest:
                    continue
                if earliest is not None and date_create < earliest:
                    continue

                # Inject the message timestamp to each entry
                # This is required for the discovery.chat.tombstone API
                alert_id = str(alert.get("id") or "")
                if "-" in alert_id:
                    alert["message_ts"] = alert_id.split("-", 1)[0]

                alerts.append(alert)

            cursor = payload.get("response_metadata", {}).get("next_cursor") or None
            if not cursor:
                break

        return alerts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Slack DLP Logs Extractor")
    parser.add_argument(
        "--slack-cookie",
        type=str,
        required=False,
        default=os.getenv("D_COOKIE", ""),
        help="Slack d cookie value (prefer env var D_COOKIE).",
    )
    parser.add_argument(
        "--enterprise-domain",
        type=str,
        required=False,
        default=os.getenv("ENTERPRISE_DOMAIN", ""),
        help="Slack enterprise domain (prefer env var ENTERPRISE_DOMAIN).",
    )
    parser.add_argument(
        "--earliest",
        type=int,
        default=None,
        help="Optional: earliest date_create epoch seconds"
    )
    parser.add_argument(
        "--latest",
        type=int,
        default=None,
        help="Optional: latest date_create epoch seconds"
    )
    args = parser.parse_args()

    if not args.slack_cookie:
        parser.error("Missing Slack cookie. Provide --slack-cookie or "
                     "set D_COOKIE environment variable.")
    if not args.enterprise_domain:
        parser.error("Missing enterprise domain. Provide --enterprise-domain or "
                     "set ENTERPRISE_DOMAIN environment variable.")

    if args.earliest is not None and args.latest is not None and args.earliest > args.latest:
        parser.error("--earliest must be <= --latest")

    return args


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    args = parse_args()
    cookie = args.slack_cookie
    domain = args.enterprise_domain
    earliest = args.earliest
    latest = args.latest

    with SlackClient(d_cookie=cookie, enterprise_domain=domain) as client:
        violations = client.get_dlp_violations(
            limit=DEFAULT_LIMIT,
            earliest=earliest,
            latest=latest
        )
        for violation in violations:
            logging.info(json.dumps(violation))


if __name__ == "__main__":
    main()
