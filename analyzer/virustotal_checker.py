"""
VirusTotal Domain Checker
=========================
Queries VirusTotal API v3 for domain reputation, detection verdicts,
and associated threat intelligence.

Requires a VT API key (free tier works — 4 req/min, 500 req/day).

Returns:
- Malicious/suspicious vendor count
- Community reputation score
- Detection categories (malware, phishing, spam, etc.)
- Last analysis stats
- Associated threat names
- WHOIS data from VT (as cross-reference)
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Optional
from datetime import datetime, timezone


class VirusTotalChecker:
    """Query VirusTotal API v3 for domain reputation data."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    def _api_get(self, endpoint: str) -> Optional[Dict]:
        """Make authenticated GET request to VT API."""
        if not self.api_key:
            return None
        url = f"{self.BASE_URL}/{endpoint}"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", self.api_key)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}", "detail": str(e.reason)}
        except urllib.error.URLError as e:
            return {"error": "Connection failed", "detail": str(e.reason)}
        except Exception as e:
            return {"error": "Unknown error", "detail": str(e)}

    def check_domain(self, domain: str) -> Dict:
        """
        Full domain reputation check via VirusTotal.

        Returns dict with:
            - vt_available: bool (API key configured and working)
            - malicious_count: int (vendors flagging as malicious)
            - suspicious_count: int (vendors flagging as suspicious)
            - harmless_count: int
            - undetected_count: int
            - total_vendors: int
            - detection_rate: float (0.0-1.0)
            - community_score: int (VT community votes)
            - categories: dict (vendor -> category mapping)
            - threat_names: list (associated malware/threat families)
            - last_analysis_date: str
            - reputation: int (VT reputation score)
            - findings: list of dicts with severity/detail
            - score: int (0-25, risk contribution)
        """
        result = {
            "vt_available": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "total_vendors": 0,
            "detection_rate": 0.0,
            "community_score": 0,
            "categories": {},
            "threat_names": [],
            "malicious_vendors": [],
            "suspicious_vendors": [],
            "last_analysis_date": None,
            "reputation": 0,
            "findings": [],
            "score": 0,
        }

        if not self.api_key:
            result["findings"].append({
                "severity": "info",
                "category": "virustotal",
                "detail": "No VirusTotal API key configured — skipping VT checks"
            })
            return result

        # ---- Domain report ----
        data = self._api_get(f"domains/{domain}")

        if not data or "error" in data:
            error_msg = data.get("detail", "Unknown error") if data else "No response"
            result["findings"].append({
                "severity": "info",
                "category": "virustotal",
                "detail": f"VT API error: {error_msg}"
            })
            return result

        attrs = data.get("data", {}).get("attributes", {})
        if not attrs:
            result["findings"].append({
                "severity": "info",
                "category": "virustotal",
                "detail": "No VT data available for this domain"
            })
            return result

        result["vt_available"] = True

        # ---- Last analysis stats ----
        stats = attrs.get("last_analysis_stats", {})
        result["malicious_count"] = stats.get("malicious", 0)
        result["suspicious_count"] = stats.get("suspicious", 0)
        result["harmless_count"] = stats.get("harmless", 0)
        result["undetected_count"] = stats.get("undetected", 0)
        result["total_vendors"] = sum(stats.values()) if stats else 0
        result["reputation"] = attrs.get("reputation", 0)

        flagged = result["malicious_count"] + result["suspicious_count"]
        if result["total_vendors"] > 0:
            result["detection_rate"] = round(flagged / result["total_vendors"], 4)

        # ---- Vendor verdicts ----
        analysis_results = attrs.get("last_analysis_results", {})
        for vendor, verdict in analysis_results.items():
            cat = verdict.get("category", "")
            if cat == "malicious":
                result["malicious_vendors"].append(vendor)
            elif cat == "suspicious":
                result["suspicious_vendors"].append(vendor)

        # ---- Categories ----
        result["categories"] = attrs.get("categories", {})

        # ---- Threat names from popular_threat_classification ----
        threat_class = attrs.get("popular_threat_classification", {})
        for label_list in [
            threat_class.get("popular_threat_name", []),
            threat_class.get("popular_threat_category", []),
        ]:
            for item in label_list:
                name = item.get("value", "")
                if name and name not in result["threat_names"]:
                    result["threat_names"].append(name)

        # ---- Community votes ----
        votes = attrs.get("total_votes", {})
        result["community_score"] = votes.get("harmless", 0) - votes.get("malicious", 0)

        # ---- Last analysis date ----
        last_ts = attrs.get("last_analysis_date")
        if last_ts:
            try:
                result["last_analysis_date"] = datetime.fromtimestamp(
                    last_ts, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
            except (ValueError, TypeError):
                result["last_analysis_date"] = str(last_ts)

        # ---- Scoring ----
        score = 0
        mal = result["malicious_count"]
        sus = result["suspicious_count"]

        if mal >= 5:
            score += 25
            result["findings"].append({
                "severity": "critical",
                "category": "virustotal",
                "detail": f"VT: {mal} vendors flag as MALICIOUS ({', '.join(result['malicious_vendors'][:5])}{'...' if mal > 5 else ''})"
            })
        elif mal >= 3:
            score += 18
            result["findings"].append({
                "severity": "high",
                "category": "virustotal",
                "detail": f"VT: {mal} vendors flag as malicious ({', '.join(result['malicious_vendors'][:5])})"
            })
        elif mal >= 1:
            score += 10
            result["findings"].append({
                "severity": "medium",
                "category": "virustotal",
                "detail": f"VT: {mal} vendor(s) flag as malicious ({', '.join(result['malicious_vendors'])})"
            })

        if sus >= 3:
            score += 8
            result["findings"].append({
                "severity": "high",
                "category": "virustotal",
                "detail": f"VT: {sus} vendors flag as suspicious ({', '.join(result['suspicious_vendors'][:5])})"
            })
        elif sus >= 1:
            score += 4
            result["findings"].append({
                "severity": "medium",
                "category": "virustotal",
                "detail": f"VT: {sus} vendor(s) flag as suspicious ({', '.join(result['suspicious_vendors'])})"
            })

        if result["threat_names"]:
            score += 5
            result["findings"].append({
                "severity": "high",
                "category": "virustotal",
                "detail": f"VT threat names: {', '.join(result['threat_names'][:5])}"
            })

        if result["community_score"] < -5:
            score += 3
            result["findings"].append({
                "severity": "medium",
                "category": "virustotal",
                "detail": f"VT community reputation negative: {result['community_score']}"
            })

        # Phishing/malware categories from vendors
        danger_categories = {"phishing", "malware", "spam", "malicious", "suspicious"}
        flagged_cats = {
            v: cat for v, cat in result["categories"].items()
            if any(d in cat.lower() for d in danger_categories)
        }
        if flagged_cats:
            score += 5
            cat_summary = ", ".join(f"{v}: {c}" for v, c in list(flagged_cats.items())[:3])
            result["findings"].append({
                "severity": "high",
                "category": "virustotal",
                "detail": f"VT vendor categories: {cat_summary}"
            })

        if mal == 0 and sus == 0 and not result["threat_names"]:
            result["findings"].append({
                "severity": "info",
                "category": "virustotal",
                "detail": f"VT: Clean — 0 malicious, 0 suspicious across {result['total_vendors']} vendors"
            })

        result["score"] = min(score, 25)
        return result
