"""
App Store Detection Module
==========================
Detects mobile app presence for a domain using three methods:

1. Deep Link Config Files:
   - /.well-known/apple-app-site-association (iOS Universal Links)
   - /.well-known/assetlinks.json (Android App Links)
   
2. Page Content Scan:
   - Finds links to apps.apple.com/app and play.google.com/store/apps
   
3. iTunes Search API:
   - Searches Apple's public API for apps matching the domain name

These are strong legitimacy signals — a domain with a verified app store
presence is very unlikely to be a throwaway spam/phishing domain.
"""

import re
import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ============================================================================
# DEEP LINK CONFIG FILE CHECKS
# ============================================================================

def check_apple_app_site_association(domain: str, timeout: float = 5.0) -> Dict:
    """
    Check for /.well-known/apple-app-site-association (AASA).
    
    This file is placed by the domain owner to register iOS Universal Links.
    Its presence proves:
    1. The domain owner has an iOS app in the App Store
    2. Apple has verified the domain-app association
    3. The domain is actively maintained for app deep linking
    
    Returns dict with:
        exists: bool - whether the file was found and valid
        app_ids: list - Apple app IDs found (format: TEAMID.bundleid)
        raw_snippet: str - first 500 chars for display
        error: str - error message if check failed
    """
    result = {
        "exists": False,
        "app_ids": [],
        "app_details": [],  # Parsed team ID + bundle ID pairs
        "raw_snippet": "",
        "error": "",
    }
    
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests library not available"
        return result
    
    # Apple checks both paths; the .well-known path is preferred
    urls = [
        f"https://{domain}/.well-known/apple-app-site-association",
        f"https://{domain}/apple-app-site-association",
    ]
    
    headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
    }
    
    for url in urls:
        try:
            resp = requests.get(url, timeout=timeout, headers=headers, verify=True, allow_redirects=True)
            
            if resp.status_code != 200:
                continue
            
            content_type = resp.headers.get('Content-Type', '').lower()
            text = resp.text.strip()
            
            # Must be JSON
            if not text.startswith('{'):
                continue
            
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            
            # Valid AASA has either "applinks" (modern) or "activitycontinuation" or "webcredentials"
            has_applinks = "applinks" in data
            has_webcredentials = "webcredentials" in data
            has_activitycontinuation = "activitycontinuation" in data
            
            # Also check for legacy format (flat "applinks" with "apps" array)
            if not (has_applinks or has_webcredentials or has_activitycontinuation):
                continue
            
            result["exists"] = True
            result["raw_snippet"] = text[:500]
            
            # Extract app IDs from various sections
            app_ids = set()
            
            # Modern format: applinks.details[].appIDs or applinks.details[].appID
            if has_applinks:
                applinks = data["applinks"]
                details = applinks.get("details", [])
                
                # details can be a list of dicts
                if isinstance(details, list):
                    for detail in details:
                        if isinstance(detail, dict):
                            # appID (singular) - newer format
                            aid = detail.get("appID", "")
                            if aid:
                                app_ids.add(aid)
                            # appIDs (plural) - older format
                            aids = detail.get("appIDs", [])
                            if isinstance(aids, list):
                                app_ids.update(a for a in aids if isinstance(a, str))
                
                # Legacy format: applinks.apps (array of app IDs)
                legacy_apps = applinks.get("apps", [])
                if isinstance(legacy_apps, list):
                    app_ids.update(a for a in legacy_apps if isinstance(a, str) and '.' in a)
            
            # webcredentials.apps
            if has_webcredentials:
                wc_apps = data["webcredentials"].get("apps", [])
                if isinstance(wc_apps, list):
                    app_ids.update(a for a in wc_apps if isinstance(a, str))
            
            # activitycontinuation.apps
            if has_activitycontinuation:
                ac_apps = data["activitycontinuation"].get("apps", [])
                if isinstance(ac_apps, list):
                    app_ids.update(a for a in ac_apps if isinstance(a, str))
            
            result["app_ids"] = sorted(app_ids)
            
            # Parse app IDs into team + bundle pairs
            for aid in result["app_ids"]:
                parts = aid.split('.', 1)
                if len(parts) == 2:
                    result["app_details"].append({
                        "team_id": parts[0],
                        "bundle_id": aid,  # Full ID including team prefix
                    })
            
            return result  # Found valid AASA, stop checking
            
        except requests.exceptions.SSLError:
            result["error"] = "SSL error checking AASA"
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection failed"
        except requests.exceptions.Timeout:
            result["error"] = "Timeout"
        except Exception as e:
            result["error"] = str(e)[:100]
    
    return result


def check_android_asset_links(domain: str, timeout: float = 5.0) -> Dict:
    """
    Check for /.well-known/assetlinks.json (Android Digital Asset Links).
    
    This file registers Android App Links. Its presence proves:
    1. The domain owner has an Android app on Google Play
    2. Google has verified the domain-app association
    3. The domain is actively maintained for app deep linking
    
    Returns dict with:
        exists: bool - whether the file was found and valid
        package_names: list - Android package names found
        raw_snippet: str - first 500 chars for display
        error: str - error message if check failed
    """
    result = {
        "exists": False,
        "package_names": [],
        "fingerprints": [],
        "raw_snippet": "",
        "error": "",
    }
    
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests library not available"
        return result
    
    url = f"https://{domain}/.well-known/assetlinks.json"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36"
    }
    
    try:
        resp = requests.get(url, timeout=timeout, headers=headers, verify=True, allow_redirects=True)
        
        if resp.status_code != 200:
            return result
        
        text = resp.text.strip()
        
        # Must be JSON array
        if not text.startswith('['):
            return result
        
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return result
        
        if not isinstance(data, list) or len(data) == 0:
            return result
        
        packages = set()
        fingerprints = []
        
        for entry in data:
            if not isinstance(entry, dict):
                continue
            
            # Check for "relation" containing "delegate_permission/common.handle_all_urls"
            # and "target" with "namespace": "android_app"
            target = entry.get("target", {})
            relation = entry.get("relation", [])
            
            if not isinstance(target, dict):
                continue
            
            namespace = target.get("namespace", "")
            package_name = target.get("package_name", "")
            
            if namespace == "android_app" and package_name:
                packages.add(package_name)
                
                # Extract SHA256 fingerprints
                fps = target.get("sha256_cert_fingerprints", [])
                if isinstance(fps, list):
                    for fp in fps:
                        if isinstance(fp, str):
                            fingerprints.append({
                                "package": package_name,
                                "fingerprint": fp[:20] + "..." if len(fp) > 20 else fp,
                            })
        
        if packages:
            result["exists"] = True
            result["package_names"] = sorted(packages)
            result["fingerprints"] = fingerprints[:10]
            result["raw_snippet"] = text[:500]
        
    except requests.exceptions.SSLError:
        result["error"] = "SSL error"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection failed"
    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)[:100]
    
    return result


# ============================================================================
# PAGE CONTENT SCAN
# ============================================================================

def scan_page_for_app_links(content: bytes, domain: str) -> Dict:
    """
    Scan page HTML content for App Store and Google Play links.
    
    Looks for:
    - Apple App Store links: apps.apple.com/app/... or itunes.apple.com/app/...
    - Google Play links: play.google.com/store/apps/details?id=...
    - Smart app banners: <meta name="apple-itunes-app" content="app-id=...">
    - Google Play badges/links in common patterns
    
    Returns dict with:
        ios_links: list of {url, app_id, app_name} dicts
        android_links: list of {url, package_name} dicts
        has_smart_banner: bool - iOS smart app banner meta tag
        smart_banner_app_id: str
    """
    result = {
        "ios_links": [],
        "android_links": [],
        "has_smart_banner": False,
        "smart_banner_app_id": "",
    }
    
    if not content:
        return result
    
    try:
        text = content.decode('utf-8', errors='ignore')
    except:
        return result
    
    # === iOS App Store Links ===
    # Pattern: https://apps.apple.com/{country}/app/{name}/id{digits}
    # Also: https://itunes.apple.com/{country}/app/{name}/id{digits}
    ios_pattern = r'https?://(?:apps|itunes)\.apple\.com/[a-z]{2}/app/([^/"\'\s]+)/id(\d+)'
    ios_matches = re.findall(ios_pattern, text, re.IGNORECASE)
    
    seen_ios = set()
    for app_name, app_id in ios_matches:
        if app_id not in seen_ios:
            seen_ios.add(app_id)
            result["ios_links"].append({
                "url": f"https://apps.apple.com/app/{app_name}/id{app_id}",
                "app_id": app_id,
                "app_name": app_name.replace('-', ' ').title(),
            })
    
    # Also catch shorter links: apps.apple.com/app/id{digits}
    ios_short = r'https?://(?:apps|itunes)\.apple\.com/app/id(\d+)'
    for app_id in re.findall(ios_short, text, re.IGNORECASE):
        if app_id not in seen_ios:
            seen_ios.add(app_id)
            result["ios_links"].append({
                "url": f"https://apps.apple.com/app/id{app_id}",
                "app_id": app_id,
                "app_name": "",
            })
    
    # === iOS Smart App Banner ===
    # <meta name="apple-itunes-app" content="app-id=123456789">
    smart_banner = re.search(
        r'<meta\s+name=["\']apple-itunes-app["\']\s+content=["\']app-id=(\d+)',
        text, re.IGNORECASE
    )
    if smart_banner:
        result["has_smart_banner"] = True
        result["smart_banner_app_id"] = smart_banner.group(1)
        # Add to iOS links if not already there
        if smart_banner.group(1) not in seen_ios:
            result["ios_links"].append({
                "url": f"https://apps.apple.com/app/id{smart_banner.group(1)}",
                "app_id": smart_banner.group(1),
                "app_name": "(from smart banner)",
            })
    
    # === Google Play Links ===
    # Pattern: https://play.google.com/store/apps/details?id=com.example.app
    play_pattern = r'https?://play\.google\.com/store/apps/details\?id=([a-zA-Z0-9._]+)'
    play_matches = re.findall(play_pattern, text, re.IGNORECASE)
    
    seen_android = set()
    for package_name in play_matches:
        if package_name not in seen_android:
            seen_android.add(package_name)
            result["android_links"].append({
                "url": f"https://play.google.com/store/apps/details?id={package_name}",
                "package_name": package_name,
            })
    
    # Limit results
    result["ios_links"] = result["ios_links"][:10]
    result["android_links"] = result["android_links"][:10]
    
    return result


# ============================================================================
# ITUNES SEARCH API
# ============================================================================

def search_itunes_for_domain(domain: str, timeout: float = 5.0) -> Dict:
    """
    Search Apple's iTunes Search API for apps matching the domain.
    
    The iTunes Search API is free, public, and doesn't require auth.
    Endpoint: https://itunes.apple.com/search?term=QUERY&entity=software&limit=5
    
    We search using the domain's brand name (e.g., "coolapp" from "coolapp.com")
    and optionally the full domain, then check if any results link back to
    a matching domain (sellerUrl or supportUrl matching).
    
    Returns dict with:
        found: bool - whether matching apps were found
        apps: list of app details
        search_term: str - what we searched for
        error: str
    """
    result = {
        "found": False,
        "apps": [],
        "search_term": "",
        "error": "",
    }
    
    if not REQUESTS_AVAILABLE:
        result["error"] = "requests library not available"
        return result
    
    # Extract brand name from domain
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        brand = parts[-2] if parts[-1] not in ('co', 'com', 'org', 'net', 'io', 'ai', 'app') or len(parts) == 2 else parts[-3] if len(parts) >= 3 else parts[0]
    else:
        brand = parts[0]
    
    # Skip very short or generic brand names
    if len(brand) < 3:
        result["error"] = f"Brand name '{brand}' too short for reliable search"
        return result
    
    search_term = brand
    result["search_term"] = search_term
    
    try:
        url = "https://itunes.apple.com/search"
        params = {
            "term": search_term,
            "entity": "software",
            "limit": 10,
        }
        
        resp = requests.get(url, params=params, timeout=timeout)
        
        if resp.status_code != 200:
            result["error"] = f"iTunes API returned {resp.status_code}"
            return result
        
        data = resp.json()
        results_list = data.get("results", [])
        
        if not results_list:
            return result
        
        domain_lower = domain.lower()
        brand_lower = brand.lower()
        
        for app in results_list:
            app_info = {
                "name": app.get("trackName", "Unknown"),
                "app_id": app.get("trackId", ""),
                "bundle_id": app.get("bundleId", ""),
                "seller": app.get("sellerName", ""),
                "seller_url": app.get("sellerUrl", ""),
                "app_url": app.get("trackViewUrl", ""),
                "icon_url": app.get("artworkUrl60", ""),
                "price": app.get("formattedPrice", ""),
                "rating": app.get("averageUserRating", 0),
                "rating_count": app.get("userRatingCount", 0),
                "description_snippet": (app.get("description", "")[:200] + "...") if app.get("description") else "",
                "match_type": "keyword",  # Will be upgraded if domain matches
            }
            
            # Check if this app is associated with our domain
            seller_url = (app.get("sellerUrl", "") or "").lower()
            support_url = (app.get("supportUrl", "") or "").lower()  # Not always in search results
            bundle_id = (app.get("bundleId", "") or "").lower()
            app_name_lower = (app.get("trackName", "") or "").lower()
            
            # Strong match: seller URL contains the domain
            if domain_lower in seller_url:
                app_info["match_type"] = "domain_match"
            # Strong match: bundle ID contains domain parts (e.g., com.coolapp.ios)
            elif brand_lower in bundle_id:
                app_info["match_type"] = "bundle_match"
            # Medium match: app name closely matches brand
            elif brand_lower in app_name_lower or app_name_lower.startswith(brand_lower):
                app_info["match_type"] = "name_match"
            
            result["apps"].append(app_info)
        
        # Sort: domain_match first, then bundle_match, then name_match, then keyword
        match_priority = {"domain_match": 0, "bundle_match": 1, "name_match": 2, "keyword": 3}
        result["apps"].sort(key=lambda a: match_priority.get(a["match_type"], 99))
        
        # Limit to top 5
        result["apps"] = result["apps"][:5]
        
        # Consider it "found" if we have at least one non-keyword match
        result["found"] = any(a["match_type"] != "keyword" for a in result["apps"])
        
    except requests.exceptions.Timeout:
        result["error"] = "iTunes API timeout"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection failed"
    except Exception as e:
        result["error"] = str(e)[:100]
    
    return result


# ============================================================================
# COMBINED APP STORE CHECK
# ============================================================================

def check_app_store_presence(domain: str, content: bytes = None, timeout: float = 5.0) -> Dict:
    """
    Run all three app store detection methods and combine results.
    
    Args:
        domain: The domain to check
        content: Page HTML content (if already fetched during analysis)
        timeout: Request timeout
    
    Returns comprehensive dict with all findings.
    """
    result = {
        # Summary flags
        "has_any_app_presence": False,
        "has_verified_deep_links": False,  # AASA or assetlinks exist
        "has_app_store_links": False,       # Links found in page
        "has_itunes_match": False,          # iTunes API found matching app
        "confidence": "none",               # none, low, medium, high
        
        # iOS
        "ios_aasa": {},
        "ios_page_links": [],
        "ios_itunes_results": {},
        
        # Android
        "android_asset_links": {},
        "android_page_links": [],
        
        # For display
        "summary_lines": [],
        
        # Flat fields for dataclass storage
        "app_store_ios_app_ids": "",      # Semicolon-separated
        "app_store_android_packages": "", # Semicolon-separated
        "app_store_methods_found": "",    # Which methods detected apps
    }
    
    methods_found = []
    all_ios_ids = set()
    all_android_packages = set()
    
    # === METHOD 1: Deep Link Config Files ===
    
    # iOS AASA
    aasa = check_apple_app_site_association(domain, timeout)
    result["ios_aasa"] = aasa
    if aasa["exists"]:
        result["has_verified_deep_links"] = True
        methods_found.append("apple_aasa")
        result["summary_lines"].append(
            f"✅ Apple App Site Association found — {len(aasa['app_ids'])} app(s) registered"
        )
        all_ios_ids.update(aasa["app_ids"])
    
    # Android Asset Links
    asset_links = check_android_asset_links(domain, timeout)
    result["android_asset_links"] = asset_links
    if asset_links["exists"]:
        result["has_verified_deep_links"] = True
        methods_found.append("android_assetlinks")
        result["summary_lines"].append(
            f"✅ Android Asset Links found — {len(asset_links['package_names'])} app(s): "
            + ", ".join(asset_links['package_names'][:3])
        )
        all_android_packages.update(asset_links["package_names"])
    
    # === METHOD 2: Page Content Scan ===
    if content:
        page_scan = scan_page_for_app_links(content, domain)
        result["ios_page_links"] = page_scan["ios_links"]
        result["android_page_links"] = page_scan["android_links"]
        
        if page_scan["ios_links"]:
            result["has_app_store_links"] = True
            methods_found.append("page_ios_links")
            names = [l["app_name"] for l in page_scan["ios_links"] if l["app_name"]]
            result["summary_lines"].append(
                f"📱 iOS App Store link(s) in page: {', '.join(names[:3]) or 'found'}"
            )
            all_ios_ids.update(l["app_id"] for l in page_scan["ios_links"])
        
        if page_scan["android_links"]:
            result["has_app_store_links"] = True
            methods_found.append("page_android_links")
            pkgs = [l["package_name"] for l in page_scan["android_links"]]
            result["summary_lines"].append(
                f"🤖 Google Play link(s) in page: {', '.join(pkgs[:3])}"
            )
            all_android_packages.update(l["package_name"] for l in page_scan["android_links"])
        
        if page_scan["has_smart_banner"]:
            methods_found.append("ios_smart_banner")
            result["summary_lines"].append(
                f"📲 iOS Smart App Banner: app ID {page_scan['smart_banner_app_id']}"
            )
    
    # === METHOD 3: iTunes Search API ===
    itunes = search_itunes_for_domain(domain, timeout)
    result["ios_itunes_results"] = itunes
    if itunes["found"]:
        result["has_itunes_match"] = True
        methods_found.append("itunes_api")
        
        best = itunes["apps"][0]
        match_desc = {
            "domain_match": "seller URL matches domain",
            "bundle_match": "bundle ID matches brand",
            "name_match": "app name matches brand",
        }.get(best["match_type"], "keyword match")
        
        result["summary_lines"].append(
            f"🍎 iTunes match: \"{best['name']}\" by {best['seller']} ({match_desc})"
        )
    elif itunes["apps"]:
        # Keyword matches only — note them but lower confidence
        result["summary_lines"].append(
            f"🔍 iTunes keyword results for \"{itunes['search_term']}\" — "
            f"{len(itunes['apps'])} app(s) found but no direct domain match"
        )
    
    # === CONFIDENCE SCORING ===
    if result["has_verified_deep_links"]:
        result["confidence"] = "high"  # AASA/assetlinks = verified by Apple/Google
    elif result["has_app_store_links"] and result["has_itunes_match"]:
        result["confidence"] = "high"  # Page links + API match
    elif result["has_app_store_links"]:
        result["confidence"] = "medium"  # Page links alone
    elif result["has_itunes_match"]:
        result["confidence"] = "medium"  # API match alone
    elif itunes.get("apps"):
        result["confidence"] = "low"  # Only keyword matches
    
    result["has_any_app_presence"] = result["confidence"] in ("medium", "high")
    
    # === FLAT FIELDS FOR STORAGE ===
    result["app_store_ios_app_ids"] = ";".join(sorted(all_ios_ids))
    result["app_store_android_packages"] = ";".join(sorted(all_android_packages))
    result["app_store_methods_found"] = ";".join(methods_found)
    
    if not result["summary_lines"]:
        result["summary_lines"].append("No app store presence detected")
    
    return result
