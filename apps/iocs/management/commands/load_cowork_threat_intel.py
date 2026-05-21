"""
Seed the ThreatIntelDomain table with the Cowork research rollup
(Google Sheets: "Cowork Threat Intel" — Domains tab, pulled 2026-04-19).

Skips `*[.]cluster` meta-entries (we don't have the expanded lists yet — when we do,
run them through this same loader under their real domains). Flags shared-abusable
hosts (pages.dev, 000webhostapp.com, eu.cc, primedatahost3.cfd) as
apex_subdomain_only=True so the detector never blocks the apex domain itself.

Idempotent: re-running updates existing rows by domain.
"""
from __future__ import annotations

from datetime import date

from django.core.management.base import BaseCommand
from django.db import transaction

from apps.iocs.models import ThreatIntelDomain


# Domains: (domain, category, subcategory, brand_target, source, reported_date, confidence, notes)
COWORK_ROLLUP = [
    ("clarkbit.com", "drainer", "crypto_drainer", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Listed in detected_urls.txt; crypto scam/drainer feed."),
    ("heonex.com", "scam", "crypto_exchange_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake exchange / investment platform."),
    ("barcodegeu.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("digigroupmine.com", "scam", "crypto_mining_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake cloud-mining scam."),
    ("saros-exchange.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake exchange scam."),
    ("keodax.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake exchange scam."),
    ("fandc.io", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("flaredropspark.com", "scam", "airdrop_scam", "flare_network", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake Flare airdrop drainer."),
    ("solana-on.com", "drainer", "wallet_drainer", "solana", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Solana-themed wallet drainer."),
    ("alternativebrokage.net", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake brokerage scam."),
    ("nexachain.top", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Generic crypto scam / .top TLD."),
    ("grimecoin.io", "scam", "token_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake token project."),
    ("sequaio.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("fivexcals.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Suspicious fintech / trading site."),
    ("peperider.com", "scam", "meme_coin_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Meme-coin rug / drainer."),
    ("canabit.ca", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake Canadian crypto platform."),
    ("buffswap.io", "drainer", "fake_dex", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake DEX drainer."),
    ("rollcoincasino.com", "scam", "casino_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake crypto casino."),
    ("siowax.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("sanctionscreen.org", "scam", "compliance_scam", "generic", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake sanctions-screening service."),
    ("nexinks.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("bitdexchain.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("crypto-pulsecce.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("onaiw3.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("tesdigital.us", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Suspicious investment platform."),
    ("drainerkits.com", "malware", "drainer_kit", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Offers / hosts crypto-drainer kits."),
    ("defilpvaults.vip", "drainer", "fake_defi", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake DeFi vault drainer; .vip TLD."),
    ("horizon-px.net", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("easyapptrade.live", "scam", "fake_trading_app", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake trading app; .live TLD."),
    ("tlnvault.com", "drainer", "fake_defi", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake vault drainer."),
    ("milltonchange.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("bggp.pro", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("digibytetrade.com", "scam", "fake_exchange", "digibyte", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "DigiByte impersonation."),
    ("dydydx.com", "phishing", "lookalike_domain", "dydx", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "dYdX typosquat drainer."),
    ("digitap.app", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("syncrobot.in", "scam", "trading_bot_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake trading-bot scam."),
    ("vexquis.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("ever-vest.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake investment platform."),
    ("praivox.pro", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("snjmmjqs.com", "suspicious", "dga_like", "unknown", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "DGA-style domain; flagged by feed."),
    ("coinbase-support.contact", "phishing", "brand_impersonation", "coinbase", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Coinbase support-impersonation phish."),
    ("nmovprsk.com", "suspicious", "dga_like", "unknown", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "DGA-style domain; flagged by feed."),
    ("pornsino.io", "scam", "casino_scam", "generic", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto casino scam."),
    ("gicah.com", "suspicious", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("primepremiumtrade.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake prime-brokerage scam."),
    ("ethmixer.lol", "scam", "mixer_scam", "ethereum", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake ETH mixer scam; .lol TLD."),
    ("edxmco.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("nasdac.vip", "phishing", "brand_impersonation", "nasdaq", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Nasdaq typosquat investment scam."),
    ("castlecoin.online", "scam", "token_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake token scam."),
    ("web3-swaps.com", "drainer", "fake_dex", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake DEX drainer."),
    ("gtcmarkvta.vip", "scam", "investment_scam", "gtc", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "GTC Markets impersonation."),
    ("gtcmarketus.cc", "scam", "investment_scam", "gtc", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "GTC Markets impersonation."),
    ("tradersutopia.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake trading platform."),
    ("foxaisniper.com", "scam", "trading_bot_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake AI sniper-bot scam."),
    ("deprop.io", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("bcexus.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("beozax.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("symfa-app.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake investment app."),
    ("asecoins.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("fedeth.shop", "scam", "crypto_scam", "ethereum", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake ETH shop / giveaway."),
    ("kaopex.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("prestige-tb.online", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake prestige-trading scam."),
    ("definft.live", "scam", "nft_scam", "generic_nft", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake NFT platform."),
    ("onocafb.top", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("finapactglobal.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake investment platform."),
    ("finapactglobal.net", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Mirror of finapactglobal.com."),
    ("firstairdrop.top", "drainer", "airdrop_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake airdrop drainer."),
    ("hyptradebitts.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake trading platform."),
    ("quantxex.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("cmegroupsdex.com", "phishing", "brand_impersonation", "cme_group", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "CME Group impersonation scam."),
    ("pyramidingfxmarket.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Pyramid FX scam."),
    ("qgkne.com", "suspicious", "dga_like", "unknown", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "DGA-style domain."),
    ("hoebeyx.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Part of a cluster (hoebey*)"),
    ("rhawj.com", "suspicious", "dga_like", "unknown", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "DGA-style domain."),
    ("hoebeys.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Part of a cluster (hoebey*)"),
    ("hoebeypro.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Part of a cluster (hoebey*)"),
    ("hoebey.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Parent of hoebey* cluster."),
    ("sljuie.com", "suspicious", "dga_like", "unknown", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "DGA-style domain."),
    ("whiua.com", "suspicious", "dga_like", "unknown", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "DGA-style domain."),
    ("maonax.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("bydfiwpf.com", "phishing", "brand_impersonation", "bydfi", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "BYDFi impersonation phish."),
    ("arrcoin.net", "scam", "token_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake token scam."),
    ("cnsweb.ltd", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Generic crypto scam; .ltd TLD."),
    ("dofowex.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("amengine.cc", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("coinlinkonline.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("fluencedrop.digital", "drainer", "airdrop_scam", "fluence", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Fake Fluence airdrop drainer."),
    ("poolkai.vip", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("v1-ledger.co.com", "phishing", "brand_impersonation", "ledger", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Ledger impersonation phish."),
    ("blazew.me", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("kenopsia.io", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("nerdlimited.com", "scam", "crypto_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Crypto scam feed entry."),
    ("fivepillarstoken.com", "scam", "token_scam", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake token scam."),
    ("goliathventuresinc.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake VC / investment scam."),
    ("edgestonetrades.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake trading platform."),
    ("ucoinbb.com", "scam", "fake_exchange", "generic_crypto", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake exchange scam."),
    ("vertexcapoption.com", "scam", "investment_scam", "generic_fintech", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake options-trading scam."),
    ("blofinhub.net", "phishing", "brand_impersonation", "blofin", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "high", "Blofin impersonation phish."),
    ("mirwd.com", "suspicious", "dga_like", "unknown", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "DGA-style domain."),
    ("deospin.com", "scam", "casino_scam", "generic", "GitHub: spmedia/Crypto-Scam-Feed", "2026-04-18", "medium", "Fake crypto casino."),
    ("boutique-dofus.fr", "phishing", "gaming_impersonation", "dofus", "GitHub: Phishing.Database (NEW-today)", "2026-04-19", "high", "French Dofus game-shop phish."),
    ("grcontestzackretsport.000webhostapp.com", "phishing", "brand_impersonation", "generic_contest", "GitHub: Phishing.Database (NEW-today)", "2026-04-19", "medium", "Free-hosting (000webhostapp) contest phish."),
    ("societegeneral-securedaccount.fr", "phishing", "banking_impersonation", "societe_generale", "GitHub: Phishing.Database (NEW-today)", "2026-04-19", "high", "Societe Generale banking credential phish."),
    ("zscaler-dev-login.pages.dev", "phishing", "brand_impersonation", "zscaler", "GitHub: criminalip/Daily-Mal-Phishing", "2026-04-19", "high", "Zscaler login phish on pages.dev."),
    ("bncrfi.eu.cc", "phishing", "banking_impersonation", "bnc", "GitHub: criminalip/Daily-Mal-Phishing", "2026-04-19", "medium", "Free .eu.cc TLD; banking-themed phish."),
    ("fr-mondial-relay.com", "phishing", "delivery_impersonation", "mondial_relay", "GitHub: criminalip/Daily-Mal-Phishing", "2026-04-19", "high", "French Mondial Relay delivery phish."),
    ("live-ldger--eng.pages.dev", "phishing", "brand_impersonation", "ledger", "PhishDestroy", "2026-04-18", "high", "Ledger Live impersonation; flagged by 7 vendors."),
    ("re-verifyrpc.pages.dev", "phishing", "wallet_verification", "generic_wallet", "PhishDestroy", "2026-04-17", "high", "Fake wallet-verification prompt."),
    ("safenetgateway.pages.dev", "phishing", "brand_impersonation", "safenet", "PhishDestroy", "2026-04-15", "medium", "Fake SafeNet gateway login."),
    ("secure-meta-mast-login.pages.dev", "phishing", "brand_impersonation", "meta", "PhishDestroy", "2026-04-14", "high", "Meta/Facebook business login phish."),
    ("astra-nucleus.pages.dev", "phishing", "brand_impersonation", "meta", "PhishDestroy", "2026-04-13", "high", "Meta business page impersonation."),
    ("meta-hyvox-483.pages.dev", "phishing", "brand_impersonation", "meta", "PhishDestroy", "2026-04-12", "high", "Meta impersonation credential phish."),
    ("ex-dustweb.pages.dev", "phishing", "brand_impersonation", "generic", "PhishDestroy", "2026-04-11", "medium", "Generic phishing on pages.dev."),
    ("ai-write.pages.dev", "phishing", "brand_impersonation", "generic_ai", "PhishDestroy", "2026-04-10", "medium", "Fake AI-writer credential phish."),
    ("gro68v.net", "drainer", "crypto_drainer", "generic_crypto", "PhishDestroy", "2026-04-03", "high", "Crypto drainer; resolves to 159.100.6.19."),
    ("gro58v-cryptoslate.com", "phishing", "brand_impersonation", "cryptoslate", "PhishDestroy", "2026-04-12", "high", "CryptoSlate impersonation drainer."),
    ("connectclevertar.com", "phishing", "generic_phish", "unknown", "PhishDestroy", "2026-04-16", "medium", "Flagged by 1 vendor."),
    ("coredomax.com", "phishing", "brand_impersonation", "coredao", "PhishDestroy", "2026-04-08", "high", "CoreDOM / Core DAO impersonation."),
    ("ro-ver.link", "phishing", "generic_phish", "unknown", "PhishDestroy", "2026-04-09", "medium", "Short-link TLD (.link)."),
    ("corevertexhub.click", "phishing", "brand_impersonation", "vertex", "PhishDestroy", "2026-04-07", "medium", "Vertex hub impersonation."),
    ("lunapex.com", "drainer", "crypto_drainer", "generic_crypto", "PhishDestroy", "2026-04-01", "high", "Crypto drainer; flagged by 2 vendors."),
    ("ledger.com.es", "phishing", "brand_impersonation", "ledger", "PhishDestroy", "2026-04-02", "high", "Ledger phish; flagged 16/95 VT."),
    ("tor-browser.io", "malware", "fake_tool", "tor_project", "Reddit / vendor disclosures", "2026-04-10", "high", "Fake Tor Browser distribution site; documented in Cyble 2026 ransomware trend report."),
    ("matamask.com", "phishing", "brand_impersonation", "metamask", "Reddit / ZachXBT / SlowMist", "2026-04-05", "high", "MetaMask typosquat drainer; linked to $107k+ theft."),
    ("metarnask.io", "phishing", "brand_impersonation", "metamask", "Reddit / SlowMist", "2026-04-05", "high", "MetaMask typosquat (rn -> m)."),
    ("metamask-support.site", "phishing", "brand_impersonation", "metamask", "Reddit r/Scams thread", "2026-04-08", "high", "Fake MetaMask support site."),
    ("incolorand.com", "malware", "c2", "lumma", "SANS ISC", "2026-04-17", "high", "Lumma Stealer / Sectop RAT C2."),
    ("goldeneagletransport.com", "malware", "c2", "lumma", "SANS ISC", "2026-04-17", "high", "Lumma Stealer C2."),
    ("arch.primedatahost3.cfd", "malware", "c2", "lumma", "SANS ISC", "2026-04-17", "high", "Lumma Stealer staging host; .cfd TLD."),
    ("gpsindia.biz", "malware", "c2", "azorult", "CYFIRMA", "2026-04-17", "high", "AZORult info-stealer C2."),
    ("wellnessmedcare.org", "malware", "apt_c2", "apt28", "Trellix", "2026-04-05", "high", "APT28 (Fancy Bear) delivery infra."),
    ("wellnesscaremed.com", "malware", "apt_c2", "apt28", "Trellix", "2026-04-05", "high", "APT28 delivery infra."),
    ("freefoodaid.com", "malware", "apt_c2", "apt28", "Trellix", "2026-04-05", "high", "APT28 delivery infra."),
    ("longsauce.com", "malware", "apt_c2", "apt28", "Trellix", "2026-04-05", "high", "APT28 delivery infra."),
    ("primedatahost3.cfd", "scan", "recon_infra", "unknown", "SANS ISC", "2026-04-17", "medium", "Host used for Lumma staging; scan/recon parent of arch.* subdomain."),
]

# Shared-abusable-host apex entries: never match the apex; only if the submission
# hostname has a prefix subdomain of one of these.
SHARED_ABUSABLE = [
    ("000webhostapp.com", "suspicious", "shared_abusable_host", "many", "Phishing.Database / general", "2026-04-19", "low", "Free shared host; abused for phishing. Score subdomains only, not apex."),
    ("pages.dev", "suspicious", "shared_abusable_host", "many", "PhishDestroy / general", "2026-04-19", "low", "Cloudflare Pages; abused for phishing. Score subdomains only, not apex."),
    ("eu.cc", "suspicious", "free_tld", "many", "Criminal IP / general", "2026-04-19", "low", "Free .eu.cc TLD; abused for phishing. Score subdomains only, not apex."),
]

# Meta-entries pointing at external expanded lists — tracked but not matchable directly.
META_CLUSTERS = [
    ("freedrain-search-phish.cluster", "phishing", "seo_drainer_cluster", "generic_wallet", "SentinelLabs / FreeDrain", "2026-04-02", "high", "FreeDrain campaign meta-entry; 38k+ malicious subdomains via SEO. Pull expanded list before ingest."),
    ("magecart-svg-exfil.cluster", "malware", "skimmer_exfil", "magento", "Sansec", "2026-04-07", "high", "Sansec: 99 compromised Magento stores + 6 exfil domains; pull Sansec's published list before ingest."),
    ("op-atlantic-approval-phish.cluster", "phishing", "approval_phishing", "crypto_wallets", "US Secret Service / NCA / RCMP", "2026-04-13", "high", "120+ domains taken down; pull full list from Operation Atlantic disclosure."),
]


class Command(BaseCommand):
    help = "Seed ThreatIntelDomain with the Cowork research rollup (idempotent)."

    def handle(self, *args, **options):
        created = updated = 0

        with transaction.atomic():
            all_rows = [(r, False, False) for r in COWORK_ROLLUP]
            all_rows += [(r, True, False) for r in SHARED_ABUSABLE]
            all_rows += [(r, False, True) for r in META_CLUSTERS]

            for row, apex_only, is_meta in all_rows:
                domain, cat, sub, brand, src, rdate, conf, notes = row
                obj, was_created = ThreatIntelDomain.objects.update_or_create(
                    domain=domain.strip().lower().rstrip("."),
                    defaults={
                        "category": cat,
                        "subcategory": sub,
                        "brand_target": brand,
                        "source": src,
                        "reported_date": date.fromisoformat(rdate),
                        "confidence": conf,
                        "notes": notes,
                        "apex_subdomain_only": apex_only,
                        "is_meta_cluster": is_meta,
                    },
                )
                if was_created:
                    created += 1
                else:
                    updated += 1

        total = ThreatIntelDomain.objects.count()
        self.stdout.write(self.style.SUCCESS(
            f"Threat-intel seeded: {created} created, {updated} updated. Total in table: {total}."
        ))
