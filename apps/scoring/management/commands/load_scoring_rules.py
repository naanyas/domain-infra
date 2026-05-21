"""
Seed the scoring_rules table with eHawk-style rules from the customer's
configuration. Idempotent: existing rules keep their edits unless --reset.

    python manage.py load_scoring_rules
    python manage.py load_scoring_rules --reset   # overwrite current_score back to seeded value
"""
from django.core.management.base import BaseCommand

from apps.scoring.models import ScoringRule
from apps.scoring.rules_seed import RULES


class Command(BaseCommand):
    help = "Seed / upsert scoring rules from apps.scoring.rules_seed.RULES."

    def add_arguments(self, parser):
        parser.add_argument("--reset", action="store_true",
                            help="Overwrite current_score for existing rules (default: preserve edits).")

    def handle(self, *args, reset: bool, **options):
        created = 0
        updated = 0
        preserved = 0
        for area, hit, default_score, current_score, description, is_implemented in RULES:
            defaults = {
                "description": description,
                "default_score": default_score,
                "current_score": current_score,
                "is_implemented": is_implemented,
            }
            obj, was_created = ScoringRule.objects.get_or_create(
                area=area, hit=hit, defaults=defaults,
            )
            if was_created:
                created += 1
                continue
            # Update description, default_score, is_implemented always.
            # Only overwrite current_score if --reset (preserves customer edits).
            obj.description = description
            obj.default_score = default_score
            obj.is_implemented = is_implemented
            if reset:
                obj.current_score = current_score
                updated += 1
            else:
                preserved += 1
            obj.save()

        total = ScoringRule.objects.count()
        self.stdout.write(self.style.SUCCESS(
            f"Loaded scoring rules: {created} created, {updated} updated, "
            f"{preserved} preserved (kept customer edits). Total in DB: {total}."
        ))
