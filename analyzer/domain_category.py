"""
Domain Category Risk Profiler
==============================
Classifies domains into business categories based on domain name
patterns, TLD signals, and page content.  Each category carries a
notification-abuse risk profile derived from observed patterns in
OneSignal's domain verification pipeline.

Risk tiers (notification-abuse likelihood):
  HIGH     -- Systematic notification abuse patterns (gambling, crypto,
              sweepstakes, MLM, adult, pharma)
  ELEVATED -- Aggressive re-engagement notifications are the core
              monetisation driver (romance serial fiction, dating)
  MODERATE -- Above-average notification volume but generally legit
              (VPN/utility apps)
  LOW      -- Unclassified or benign categories

Integration
-----------
Called from analyze_domain() after content fetch + app store check.
Results stored on DomainApprovalResult and consumed by
calculate_score() as a signal that can amplify other risk indicators.

v7.7.0 -- Initial implementation.
          Targets romance serial fiction cluster first
          (swoon-stories.app, lovelit.app, novelle-stories.app ...)
v7.8   -- FIX: Short keyword false positives.
          1) Substring matching (domain_flat) now requires keywords ≥5
             chars.  Short keywords (keto, bet, diet, cam, eth, date, ...)
             only match as exact domain words (split on hyphens/dots).
             Prevents "keto" matching "ticketoo", "bet" matching
             "alphabet", "diet" matching "audited", etc.
          2) Prefix-style regex patterns: removed short keywords that
             are common English word prefixes (bet→better, cam→camera,
             win→window, free→freedom, date→update, diet→dietrich,
             defi→definite).  Longer variants or exact word matching
             cover the intended detection.
          3) Suffix-style regex patterns: removed ≤4 char keywords
             that match as natural word endings (bet in alphabet,
             date in mandate).
"""

import re
import logging

logger = logging.getLogger(__name__)

# ====================================================================
# CATEGORY DEFINITIONS
# ====================================================================
# domain_keywords  -- words in domain name (split on hyphens/dots)
# domain_patterns  -- regex patterns against full domain string
# tld_boost        -- TLDs that raise confidence for this category
# content_keywords -- phrases in page title / visible body text
# risk_tier        -- HIGH | ELEVATED | MODERATE | LOW
# risk_reason      -- human-readable justification
# base_score       -- points added when confidence >= threshold

CATEGORIES = {
    "romance_serial_fiction": {
        "label": "Romance/Serial Fiction App",
        "domain_keywords": [
            "novel", "stories", "story", "romance", "swoon", "lovelit",
            "novelle", "amora", "lunara", "richnovel", "noirlit", "fling",
            "chapters", "episode", "dreame", "webnovel", "inkitt",
            "serialread", "readrom", "bookish", "hotreads", "passionread",
            "romancely", "lovestory", "readlove",
        ],
        "domain_patterns": [
            r"\b(?:love|romance|passion|desire|swoon|amora|noir)\w*(?:lit|read|novel|book|story|stories)",
            r"\w+[-.]stories\.",
            r"\w+[-.]novels?\.",
            r"\w+[-.]reads?\.",
            r"\b(?:read|book|novel)\w+\.app$",
        ],
        "tld_boost": [".app", ".io", ".club"],
        "content_keywords": [
            "romance novel", "love story", "romance audiobook",
            "serial fiction", "unlock chapter", "billionaire romance",
            "werewolf romance", "alpha romance", "enemies to lovers",
            "forced proximity", "slow burn", "premium chapter",
            "continue reading", "next chapter", "daily update",
            "new chapter", "coins", "unlock",
        ],
        "risk_tier": "ELEVATED",
        "risk_reason": "Serial fiction apps use aggressive chapter-unlock notifications as core monetisation; high volume with manufactured urgency",
        "base_score": 12,
    },

    "gambling_betting": {
        "label": "Gambling/Betting",
        "domain_keywords": [
            "bet", "bets", "betting", "casino", "poker", "slots",
            "gamble", "gambling", "jackpot", "roulette", "blackjack",
            "sportsbet", "wager", "bookie", "odds", "punt",
        ],
        "domain_patterns": [
            r"\b(?:casino|poker|slots?|gambl|betting|wager)[-\w]*\.",
            r"\w+(?:casino|poker|slots|betting|gamble)\.",
            r"\bbet\d",                                          # bet365, bet9ja, bet777
            r"(?:sports|live|lucky|super|mega|power|royal|golden)\w*bet\.",  # sportsbet, livebet
        ],
        "tld_boost": [".bet", ".casino", ".games", ".win"],
        "content_keywords": [
            "place your bet", "free spins", "deposit bonus",
            "welcome bonus", "sports betting", "live casino",
            "slot machine", "jackpot", "wager", "payout",
            "responsible gambling", "gambleaware",
        ],
        "risk_tier": "HIGH",
        "risk_reason": "Gambling sites use notifications for bet prompts, deposit bonuses, and event alerts; high regulatory and spam risk",
        "base_score": 15,
    },

    "crypto_trading": {
        "label": "Crypto/Trading Platform",
        "domain_keywords": [
            "crypto", "bitcoin", "btc", "eth", "token", "defi", "nft",
            "forex", "trading", "trade", "exchange", "swap", "yield",
            "stake", "staking", "wallet", "mining",
        ],
        "domain_patterns": [
            r"\b(?:crypto|bitcoin|forex|trading)[-\w]*\.",
            r"\w+(?:exchange|token|trade|swap)\.",
        ],
        "tld_boost": [".finance", ".exchange", ".trading", ".crypto"],
        "content_keywords": [
            "cryptocurrency", "bitcoin", "ethereum", "blockchain",
            "trading platform", "forex", "leverage", "deposit now",
            "start trading", "price alert", "portfolio",
            "market cap", "tokenomics",
        ],
        "risk_tier": "HIGH",
        "risk_reason": "Crypto/trading platforms use notifications for price alerts, deposit prompts, and FOMO engagement; high scam risk",
        "base_score": 15,
    },

    "dating": {
        "label": "Dating/Matchmaking",
        "domain_keywords": [
            "dating", "date", "singles", "hookup", "flirt", "cupid",
            "lovematch", "meetme", "chatmate", "soulmate",
        ],
        "domain_patterns": [
            r"\b(?:dating|flirt|singles|hookup|cupid)[-\w]*\.",
            r"\w+(?:dating|match)\.",
        ],
        "tld_boost": [".dating", ".singles", ".love"],
        "content_keywords": [
            "find your match", "start dating", "singles near",
            "swipe right", "meet singles", "someone liked you",
            "new match", "message waiting",
        ],
        "risk_tier": "ELEVATED",
        "risk_reason": "Dating apps use notifications for match alerts and FOMO engagement; frequent spam and fake-profile abuse vector",
        "base_score": 10,
    },

    "rewards_sweepstakes": {
        "label": "Rewards/Sweepstakes",
        "domain_keywords": [
            "sweepstakes", "giveaway", "freebie", "reward", "rewards",
            "prize", "winner", "raffle", "contest", "cashback",
            "freegift", "winprize",
        ],
        "domain_patterns": [
            r"\b(?:prize|reward|sweep|giveaway)[-\w]*\.",
            r"\w+(?:rewards?|prize|giveaway|sweeps)\.",
        ],
        "tld_boost": [".win", ".gift", ".promo"],
        "content_keywords": [
            "congratulations", "you won", "claim your prize",
            "free gift", "sweepstakes", "giveaway", "enter to win",
            "spin the wheel", "lucky winner", "limited time",
        ],
        "risk_tier": "HIGH",
        "risk_reason": "Sweepstakes/rewards sites are a top vector for notification spam, misleading claims, and data harvesting",
        "base_score": 15,
    },

    "mlm_money": {
        "label": "MLM/Make-Money Scheme",
        "domain_keywords": [
            "earnmoney", "makemoney", "getrich", "passive", "income",
            "mlm", "affiliate", "cashflow", "sidehustle",
            "financialfreedom", "residual",
        ],
        "domain_patterns": [
            r"\b(?:earn|make|get)(?:money|cash|rich|paid)[-\w]*\.",
            r"\b(?:passive|residual)(?:income|cash|earn)[-\w]*\.",
        ],
        "tld_boost": [".money", ".cash", ".finance"],
        "content_keywords": [
            "make money", "passive income", "financial freedom",
            "work from home", "earn from home", "side hustle",
            "downline", "network marketing", "residual income",
            "get paid", "easy money",
        ],
        "risk_tier": "HIGH",
        "risk_reason": "MLM/money schemes use notifications for recruitment prompts, urgency creation, and misleading earnings claims",
        "base_score": 15,
    },

    "adult_content": {
        "label": "Adult Content",
        "domain_keywords": [
            "xxx", "porn", "adult", "nsfw", "cam", "webcam",
            "escort", "erotic", "sexy",
        ],
        "domain_patterns": [
            r"\b(?:xxx|porn|adult|nsfw|webcam|erotic|sexy)[-\w]*\.",
        ],
        "tld_boost": [".xxx", ".adult", ".sex", ".porn"],
        "content_keywords": [
            "adult content", "nsfw", "webcam", "explicit",
        ],
        "risk_tier": "HIGH",
        "risk_reason": "Adult content notifications violate platform policies and create brand safety risk for OneSignal infrastructure",
        "base_score": 15,
    },

    "pharmaceutical": {
        "label": "Pharmaceutical/Supplements",
        "domain_keywords": [
            "pharmacy", "pharma", "pills", "supplement", "diet",
            "weightloss", "keto", "cbd", "viagra", "cialis",
            "nootropic", "detox",
        ],
        "domain_patterns": [
            r"\b(?:pharma|pills?|supplement|keto|cbd|viagra)[-\w]*\.",
        ],
        "tld_boost": [".health", ".pharmacy"],
        "content_keywords": [
            "prescription", "pharmacy", "weight loss", "supplement",
            "diet pill", "limited stock", "order now",
        ],
        "risk_tier": "HIGH",
        "risk_reason": "Pharmaceutical/supplement sites use notifications for purchase urgency, fake scarcity, and unregulated health claims",
        "base_score": 12,
    },

    "vpn_utility": {
        "label": "VPN/Utility App",
        "domain_keywords": [
            "vpn", "proxy", "cleaner", "booster", "antivirus",
            "securevpn", "fastvpn",
        ],
        "domain_patterns": [
            r"\b(?:vpn|proxy|cleaner|booster|antivirus)[-\w]*\.",
            r"\w+(?:vpn|proxy|cleaner|booster)\.",
        ],
        "tld_boost": [".app", ".tech"],
        "content_keywords": [
            "vpn", "proxy", "secure connection", "clean your phone",
            "boost speed", "battery saver", "virus scan",
        ],
        "risk_tier": "MODERATE",
        "risk_reason": "Utility apps use notifications for scare-based engagement; moderate abuse potential",
        "base_score": 5,
    },
}


# ====================================================================
# CLASSIFICATION ENGINE
# ====================================================================

def _extract_domain_words(domain):
    """Split domain into component words for keyword matching.

    swoon-stories.app  ->  ['swoon', 'stories']
    richnovel.app      ->  ['richnovel']
    """
    parts = domain.lower().split(".")
    # Strip TLD (and SLD like .co.uk)
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net"):
        name_parts = parts[:-2]
    elif len(parts) >= 2:
        name_parts = parts[:-1]
    else:
        name_parts = parts
    words = []
    for part in name_parts:
        words.extend(part.split("-"))
    return [w for w in words if w]


def _get_tld(domain):
    """Return TLD with leading dot, e.g. '.app'."""
    parts = domain.lower().split(".")
    return "." + parts[-1] if len(parts) >= 2 else ""


def classify_domain(
    domain,
    page_title="",
    page_content_text="",
    app_store_packages="",
    custom_categories=None,
):
    """
    Classify a domain into a business category and return risk profile.

    Confidence scoring (higher = more certain):
      Domain keyword match:  +2 per keyword  (max 3 counted = 6)
      Domain regex match:    +3              (max 1 counted = 3)
      TLD boost:             +1
      Content keyword match: +2 per keyword  (max 4 counted = 8)
                                              Theoretical max = 18

    Minimum confidence of 3 to assign a category.

    Returns dict:
      category          -- category key or 'unclassified'
      category_label    -- human-readable label
      confidence        -- 0-18
      risk_tier         -- HIGH | ELEVATED | MODERATE | LOW
      risk_reason       -- why this category is risky
      base_score        -- points to add in scoring
      matched_signals   -- list of what triggered the match
    """
    cats = custom_categories or CATEGORIES

    result = {
        "category": "unclassified",
        "category_label": "",
        "confidence": 0,
        "risk_tier": "LOW",
        "risk_reason": "",
        "base_score": 0,
        "matched_signals": [],
    }

    domain_lower = domain.lower()
    domain_words = _extract_domain_words(domain)
    tld = _get_tld(domain)
    domain_flat = domain_lower.replace(".", "").replace("-", "")

    content_combined = " ".join([
        page_title.lower() if page_title else "",
        page_content_text[:3000].lower() if page_content_text else "",
    ])

    best_cat = None
    best_conf = 0
    best_sigs = []

    for cat_key, cat_def in cats.items():
        conf = 0
        sigs = []

        # --- Domain keyword matching (max 3 x 2pts = 6) ---
        # Two matching modes:
        #   1. Exact word match (domain_words) — always safe, any length
        #   2. Substring match (domain_flat) — catches compounds like
        #      "sportsbetking" but ONLY for keywords ≥5 chars.  Short
        #      keywords produce false positives inside unrelated words:
        #        "keto" in "ticketoo"  |  "bet" in "alphabet"
        #        "diet" in "audited"   |  "cam" in "camera"
        _SUBSTR_MIN_LEN = 5
        kw_hits = 0
        for kw in cat_def.get("domain_keywords", []):
            if kw in domain_words:
                kw_hits += 1
                sigs.append("domain_word:" + kw)
            elif len(kw) >= _SUBSTR_MIN_LEN and kw in domain_flat:
                kw_hits += 1
                sigs.append("domain_substr:" + kw)
            if kw_hits >= 3:
                break
        conf += min(kw_hits, 3) * 2

        # --- Domain regex patterns (max 1 x 3pts) ---
        for pat in cat_def.get("domain_patterns", []):
            try:
                if re.search(pat, domain_lower):
                    conf += 3
                    sigs.append("domain_pattern")
                    break
            except re.error:
                continue

        # --- TLD boost (1pt) ---
        if tld in cat_def.get("tld_boost", []):
            conf += 1
            sigs.append("tld_boost:" + tld)

        # --- Content keyword matching (max 4 x 2pts = 8) ---
        if content_combined.strip():
            ck_hits = 0
            for ckw in cat_def.get("content_keywords", []):
                if ckw.lower() in content_combined:
                    ck_hits += 1
                    sigs.append("content:" + ckw[:30])
                    if ck_hits >= 4:
                        break
            conf += min(ck_hits, 4) * 2

        if conf > best_conf:
            best_conf = conf
            best_cat = cat_key
            best_sigs = sigs

    # Minimum threshold
    if best_cat and best_conf >= 3:
        cdef = cats[best_cat]
        result["category"] = best_cat
        result["category_label"] = cdef.get("label", best_cat)
        result["confidence"] = best_conf
        result["risk_tier"] = cdef.get("risk_tier", "LOW")
        result["risk_reason"] = cdef.get("risk_reason", "")
        result["base_score"] = cdef.get("base_score", 0)
        result["matched_signals"] = best_sigs

    return result
