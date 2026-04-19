"""
Download / refresh MaxMind GeoLite2 MMDB files to MAXMIND_DB_DIR.

Run weekly (MaxMind publishes Tuesday + Friday). In prod, trigger via cron/systemd timer.

    python manage.py update_geoip
    python manage.py update_geoip --editions GeoLite2-City,GeoLite2-ASN
"""
from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from pathlib import Path

import requests
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

DEFAULT_EDITIONS = ("GeoLite2-City", "GeoLite2-ASN", "GeoLite2-Country")
DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id={edition}&license_key={key}&suffix=tar.gz"
)


class Command(BaseCommand):
    help = "Download / refresh MaxMind GeoLite2 MMDB databases into MAXMIND_DB_DIR."

    def add_arguments(self, parser):
        parser.add_argument(
            "--editions",
            default=",".join(DEFAULT_EDITIONS),
            help="Comma-separated list of editions to refresh.",
        )
        parser.add_argument("--force", action="store_true", help="Re-download even if file exists.")

    def handle(self, *args, editions: str, force: bool, **options):
        key = os.environ.get("MAXMIND_LICENSE_KEY", "")
        if not key:
            raise CommandError("MAXMIND_LICENSE_KEY not set in environment/.env")

        db_dir = Path(os.environ.get("MAXMIND_DB_DIR") or (Path(settings.BASE_DIR) / "geoip"))
        db_dir.mkdir(parents=True, exist_ok=True)

        for edition in [e.strip() for e in editions.split(",") if e.strip()]:
            target = db_dir / f"{edition}.mmdb"
            if target.exists() and not force:
                self.stdout.write(self.style.NOTICE(f"exists, skipping (use --force): {target}"))
                continue

            url = DOWNLOAD_URL.format(edition=edition, key=key)
            self.stdout.write(f"downloading {edition} ...")
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                archive = tmp_path / f"{edition}.tar.gz"
                resp = requests.get(url, stream=True, timeout=120)
                resp.raise_for_status()
                with open(archive, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=64 * 1024):
                        if chunk:
                            f.write(chunk)

                # Archive layout: {edition}_YYYYMMDD/{edition}.mmdb
                with tarfile.open(archive, "r:gz") as tar:
                    tar.extractall(tmp_path)  # noqa: S202 — MaxMind-trusted archive

                # Locate the .mmdb file inside the extracted dir
                for mmdb in tmp_path.rglob("*.mmdb"):
                    shutil.move(str(mmdb), str(target))
                    break
                else:
                    raise CommandError(f"No .mmdb file found in archive for {edition}")

            size_mb = target.stat().st_size / (1024 * 1024)
            self.stdout.write(self.style.SUCCESS(f"  -> {target} ({size_mb:.1f} MB)"))

        self.stdout.write(self.style.SUCCESS("done."))
