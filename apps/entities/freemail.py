"""
Curated list of major free email providers. SDAT analyzer is SKIPPED on these
domains — scanning gmail.com/yahoo.com/etc. every time produces no signal.

Expand as customer data surfaces more freemail providers. Disposable domains
are handled separately via disposable-email-domains package.
"""
FREEMAIL_DOMAINS: frozenset[str] = frozenset({
    # Google
    "gmail.com", "googlemail.com",
    # Yahoo family
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.co.in", "yahoo.com.br",
    "yahoo.ca", "yahoo.es", "yahoo.com.mx", "yahoo.com.au", "ymail.com", "rocketmail.com",
    # Microsoft
    "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de", "hotmail.it", "hotmail.es",
    "outlook.com", "outlook.co.uk", "outlook.fr", "live.com", "live.co.uk", "live.nl",
    "msn.com",
    # Apple
    "icloud.com", "me.com", "mac.com",
    # AOL
    "aol.com", "aol.co.uk",
    # Proton
    "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
    # Generic free providers
    "mail.com", "email.com", "gmx.com", "gmx.net", "gmx.de", "gmx.at",
    "web.de", "t-online.de", "freenet.de",
    "fastmail.com", "fastmail.fm",
    "zoho.com", "zohomail.com",
    # Privacy-focused
    "tutanota.com", "tuta.io", "tutanota.de",
    # Asia
    "qq.com", "163.com", "126.com", "sina.com", "sina.cn", "sohu.com", "aliyun.com",
    "yandex.com", "yandex.ru", "ya.ru", "mail.ru", "bk.ru", "list.ru", "inbox.ru",
    "naver.com", "daum.net", "hanmail.net", "nate.com",
    # Other regions
    "rediffmail.com", "indiatimes.com",
    "laposte.net", "orange.fr", "wanadoo.fr", "free.fr", "sfr.fr", "neuf.fr",
    "libero.it", "virgilio.it", "tiscali.it", "alice.it",
    "mail.ee", "inbox.lv", "centrum.cz", "seznam.cz",
    # Commonly-abused though technically disposable-ish
    "hey.com",
})


def is_freemail(domain: str) -> bool:
    return (domain or "").lower().strip() in FREEMAIL_DOMAINS
