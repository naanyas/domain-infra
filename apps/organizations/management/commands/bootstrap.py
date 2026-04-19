"""
Create a test organization + API key. Idempotent on (slug): reuses an existing
org of the same slug and mints a fresh API key each run so you always get
a copy-pasteable credential.

    python manage.py bootstrap --slug acme --name "Acme Corp" --label "local-test"
"""
from django.core.management.base import BaseCommand

from apps.organizations.models import ApiKey, Organization


class Command(BaseCommand):
    help = "Create or refresh a test organization and print a fresh API key."

    def add_arguments(self, parser):
        parser.add_argument("--slug", default="acme", help="Organization slug")
        parser.add_argument("--name", default="Acme Corp", help="Organization display name")
        parser.add_argument("--label", default="local-test", help="API key label")

    def handle(self, *args, slug: str, name: str, label: str, **options):
        org, created = Organization.objects.get_or_create(
            slug=slug, defaults={"name": name}
        )
        created_str = "created" if created else "existing"
        self.stdout.write(self.style.SUCCESS(f"Organization {created_str}: {org} (id={org.id})"))

        api_key, raw = ApiKey.generate(org, label=label)
        self.stdout.write(self.style.SUCCESS(f"ApiKey created: label={label}, prefix={api_key.key_prefix}"))
        self.stdout.write("")
        self.stdout.write(self.style.WARNING("Raw API key (shown once — save it now):"))
        self.stdout.write(self.style.WARNING(f"  {raw}"))
        self.stdout.write("")
        self.stdout.write("Try it:")
        self.stdout.write(
            f'  curl -X POST http://localhost:8000/api/v1/submissions?wait=true \\\n'
            f'    -H "X-API-Key: {raw}" \\\n'
            f'    -H "Content-Type: application/json" \\\n'
            f'    -d \'{{"domain":"example.com"}}\''
        )
