"""
Refresh external threat-intel feeds. Pulls any feed whose refresh interval has
elapsed (or all if --force) and upserts into ThreatIntelDomain.

Scheduling: add a crontab entry —
    */30 * * * * cd /path/to/domain-infra && .venv/bin/python manage.py refresh_threat_intel

Or a systemd timer. No Celery / Redis required.
"""
from django.core.management.base import BaseCommand

from apps.iocs.fetchers import fetch_feed, refresh_due_feeds
from apps.iocs.models import ThreatIntelFeed


class Command(BaseCommand):
    help = "Refresh external threat-intel feeds that are due."

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true",
                            help="Ignore refresh_interval_hours and refresh every enabled feed.")
        parser.add_argument("--feed", default="",
                            help="Refresh only the named feed (exact match).")
        parser.add_argument("--limit", type=int, default=0,
                            help="Cap items per feed (useful for dry-run smoke tests).")

    def handle(self, *args, force: bool, feed: str, limit: int, **opts):
        if feed:
            try:
                f = ThreatIntelFeed.objects.get(name=feed)
            except ThreatIntelFeed.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"No feed named {feed!r}"))
                return
            res = fetch_feed(f, limit=limit or None)
            self.stdout.write(f"{feed}: {res}")
            return

        results = refresh_due_feeds(force=force)
        if not results:
            self.stdout.write("No feeds were due.")
            return
        for res in results:
            style = self.style.SUCCESS if res.get("status") == "ok" else self.style.ERROR
            self.stdout.write(style(
                f"{res.get('feed','?')}: {res.get('status')} "
                f"(created={res.get('created',0)} updated={res.get('updated',0)} "
                f"skipped={res.get('skipped',0)} in {res.get('duration_seconds','?')}s)"
            ))
