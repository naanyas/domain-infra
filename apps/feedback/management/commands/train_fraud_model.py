"""
Train the fraud classifier on every investigator-labeled TrainingLabel.

Usage:
    python manage.py train_fraud_model
    python manage.py train_fraud_model --org acme

Fits a gradient-boosted trees classifier to predict p(fraud) given the frozen
feature snapshot on each label row. Persists the model to ml_models/.
"""
from __future__ import annotations

import json

from django.core.management.base import BaseCommand

from apps.feedback.ml import train_model
from apps.feedback.models import TrainingLabel


class Command(BaseCommand):
    help = "Train the fraud classifier on accumulated TrainingLabels."

    def add_arguments(self, parser):
        parser.add_argument("--org", default="", help="Only train on labels from this org slug")

    def handle(self, *args, org: str = "", **opts):
        qs = TrainingLabel.objects.all()
        if org:
            qs = qs.filter(organization__slug=org)
        self.stdout.write(f"Total labels: {qs.count()}")
        meta = train_model(qs)
        self.stdout.write(json.dumps(meta, indent=2, default=str))
        status = meta.get("status")
        if status == "trained":
            self.stdout.write(self.style.SUCCESS(
                f"✓ Trained. accuracy={meta.get('accuracy'):.3f} auc={meta.get('auc')} "
                f"n_train={meta.get('n_train')} n_test={meta.get('n_test')}"
            ))
        else:
            self.stdout.write(self.style.WARNING(f"⚠ {status}: {meta.get('reason')}"))
