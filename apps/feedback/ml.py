"""
ML training + inference on the TrainingLabel corpus.

This is a real classifier — not a heuristic. Architecture:

  TrainingLabels (JSON features)
       │
       ▼  vectorize_features()  ── turns JSON → numeric vector
       ▼
  scikit-learn pipeline (gradient-boosted trees by default)
       │
       ▼  joblib.dump() → ml_models/fraud_classifier.joblib
       ▼
  predict_fraud_probability(submission) ── called by process_submission
       │
       ▼  returns p(bad) in [0,1], used to adjust the score

Training requirements:
  - At least 100 non-unknown labels, with ≥20 of each class (approve/deny).
    Under that threshold we DON'T train (returns None and the pipeline falls back
    to pure rule-based scoring).
  - Re-train by running: `python manage.py train_fraud_model`.
  - Inference is cache-on-first-use; the saved model is hot-reloaded when its
    mtime changes, so a fresh train takes effect without a server restart.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)

# Model persistence
MODEL_DIR = Path(getattr(settings, "BASE_DIR", Path("."))) / "ml_models"
MODEL_PATH = MODEL_DIR / "fraud_classifier.joblib"
METADATA_PATH = MODEL_DIR / "fraud_classifier.meta.json"

# Don't train unless we have this many labels with class balance.
MIN_LABELS_TOTAL = 100
MIN_LABELS_PER_CLASS = 20


# ======================================================================
# Feature extraction — the ONLY place that maps JSON → numeric vector.
# Keep this stable; trainers and inference must agree exactly.
# ======================================================================


NUMERIC_FEATURE_NAMES = [
    "score",
    "domain_age_days",
    "content_visible_word_count",
    "ct_log_count",
    "ct_days_since_last_cert",
    "hacklink_score",
    "vt_malicious_count",
    "vt_suspicious_count",
    "vt_community_score",
    "vt_reputation",
    "vt_external_malicious_count",
    "ipqs_fraud_score",
    "ipqs_overall_score",
    "email_net_flagged",
    "email_net_approved",
    "ip_net_flagged",
    "ip_net_approved",
    "fingerprint_reputation",
]

# Flat boolean flags pulled from raw SDAT + entities.
BOOLEAN_FEATURE_NAMES = [
    "content_title_body_mismatch",
    "content_is_facade",
    "content_is_broker_page",
    "content_is_placeholder",
    "phishing_kit_detected",
    "hacklink_detected",
    "malicious_script",
    "hidden_injection",
    "has_oauth_phish",
    "is_homoglyph_domain",
    "quishing_profile",
    "cdn_tunnel_suspect",
    "domain_transfer_lock_recent",
    "whois_recently_updated",
    "mx_provider_mismatch",
    "subdomain_infra_divergent",
    "ct_recent_issuance",
    "brand_plus_keyword_domain",
    "tld_variant_spoofing",
    "domain_reregistered",
    "registration_opaque",
    "ip_is_vpn",
    "ip_is_proxy",
    "ip_is_tor",
    "ip_is_datacenter",
    "ip_bot_status",
    "email_is_disposable",
    "email_is_role_based",
    "email_is_freemail",
    "email_ipqs_honeypot",
    "email_ipqs_leaked",
    "email_ipqs_recent_abuse",
    # Direct threat-intel match signals — a known-bad domain hitting on the
    # submission's domain or its cross-links / email domain.
    "threat_intel_matched",
    "threat_intel_high_confidence_match",
]

# Numeric threat-intel features appended at end so trainers keep a stable order.
NUMERIC_FEATURE_NAMES_EXTRA = [
    "threat_intel_match_count",
    "threat_intel_total_score",
]

CATEGORICAL_FEATURE_NAMES = [
    "email_tag",        # "", "good", "bad", "do_not_score"
    "ip_tag",
    "phone_tag",
    "name_tag",
    "ip_country",       # ISO2
    "email_domain_tld",
    # Threat-intel category + confidence of the top hit (if any)
    "threat_intel_top_category",   # "phishing", "malware", "drainer", ..., or ""
    "threat_intel_top_confidence", # "high", "medium", "low", or ""
]


def _safe_float(v, default=0.0):
    try:
        f = float(v)
        return f if f == f else default   # NaN guard
    except (TypeError, ValueError):
        return default


def _safe_bool(v):
    if isinstance(v, bool):
        return 1 if v else 0
    if v in (None, "", 0, "0", "false", "False", "no", "No", "none", "None"):
        return 0
    return 1


def _get(d, *keys, default=None):
    """Deep-get; first matching key path wins."""
    for k in keys:
        parts = k.split(".")
        cur = d
        ok = True
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                ok = False
                break
        if ok:
            return cur
    return default


def vectorize_features(features: dict[str, Any]) -> dict[str, float]:
    """
    Turn a TrainingLabel.features JSON into a flat {column_name: numeric_value}
    dict. Fixed column order defined by NUMERIC_/BOOLEAN_/CATEGORICAL_FEATURE_NAMES.
    Categoricals are one-hot encoded at training time — here we just emit the raw
    string value; the sklearn ColumnTransformer handles the encoding.
    """
    raw_scan = _get(features, "domain_scan.raw_result", default={}) or {}
    verdict = _get(features, "verdict", default={}) or {}
    email = _get(features, "contact_email", default={}) or {}
    phone = _get(features, "contact_phone", default={}) or {}
    name_e = _get(features, "contact_name", default={}) or {}
    ip = _get(features, "submitter_ip", default={}) or {}
    fps = _get(features, "fingerprints", default=[]) or []
    fp_rep = max((f.get("reputation") or 0.0 for f in fps), default=0.0)

    row: dict[str, Any] = {}

    # Numeric
    row["score"]                         = _safe_float(verdict.get("score"))
    row["domain_age_days"]               = _safe_float(raw_scan.get("domain_age_days"), -1)
    row["content_visible_word_count"]    = _safe_float(raw_scan.get("content_visible_word_count"), -1)
    row["ct_log_count"]                  = _safe_float(raw_scan.get("ct_log_count"), -1)
    row["ct_days_since_last_cert"]       = _safe_float(raw_scan.get("ct_days_since_last_cert"), -1)
    row["hacklink_score"]                = _safe_float(raw_scan.get("hacklink_score"))
    row["vt_malicious_count"]            = _safe_float(raw_scan.get("vt_malicious_count"))
    row["vt_suspicious_count"]           = _safe_float(raw_scan.get("vt_suspicious_count"))
    row["vt_community_score"]            = _safe_float(raw_scan.get("vt_community_score"))
    row["vt_reputation"]                 = _safe_float(raw_scan.get("vt_reputation"))
    row["vt_external_malicious_count"]   = _safe_float(raw_scan.get("vt_external_malicious_count"))
    row["ipqs_fraud_score"]              = _safe_float(ip.get("fraud_score"))
    row["ipqs_overall_score"]            = _safe_float(email.get("ipqs_overall_score"), -1)
    row["email_net_flagged"]             = _safe_float(email.get("net_flagged"))
    row["email_net_approved"]            = _safe_float(email.get("net_approved"))
    row["ip_net_flagged"]                = _safe_float(ip.get("net_flagged"))
    row["ip_net_approved"]               = _safe_float(ip.get("net_approved"))
    row["fingerprint_reputation"]        = _safe_float(fp_rep)

    # Boolean
    for k in BOOLEAN_FEATURE_NAMES:
        if k.startswith("email_"):
            src, field = email, k[len("email_"):]
        elif k.startswith("ip_"):
            src, field = ip, k[len("ip_"):]
        else:
            src, field = raw_scan, k
        row[k] = _safe_bool(src.get(field))

    # Categorical — emit as strings
    row["email_tag"] = (email.get("tag") or "").strip()
    row["ip_tag"]    = (ip.get("tag") or "").strip()
    row["phone_tag"] = (phone.get("tag") or "").strip()
    row["name_tag"]  = (name_e.get("tag") or "").strip()
    row["ip_country"] = (ip.get("country") or "").strip().upper()[:2]
    # Email domain TLD
    dom = (email.get("domain") or "").lower().strip()
    row["email_domain_tld"] = dom.split(".")[-1] if "." in dom else ""

    # ── Threat-intel match signals — pulled from the verdict reasons list. ──
    # The scoring pipeline emits a reason with code="threat_intel_*" for every
    # hit, including a nested `detail` dict (confidence, category, score).
    # The classifier consumes these as explicit features so the learning loop
    # can distinguish "scored high because of SDAT" from "scored high because
    # the domain is on our known-threats list."
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    ti_count = 0
    ti_total_score = 0
    top_conf_rank = 0
    top_conf = ""
    top_cat = ""
    for reason in verdict.get("reasons") or []:
        if not isinstance(reason, dict):
            continue
        code = str(reason.get("code") or "")
        if not code.startswith("threat_intel_"):
            continue
        ti_count += 1
        try:
            ti_total_score += int(reason.get("weight") or 0)
        except (TypeError, ValueError):
            pass
        detail = reason.get("detail") or {}
        conf = str(detail.get("confidence") or "").lower()
        rank = confidence_rank.get(conf, 0)
        if rank > top_conf_rank:
            top_conf_rank = rank
            top_conf = conf
            top_cat = str(detail.get("category") or "")

    row["threat_intel_matched"] = 1 if ti_count else 0
    row["threat_intel_high_confidence_match"] = 1 if top_conf == "high" else 0
    row["threat_intel_match_count"] = float(ti_count)
    row["threat_intel_total_score"] = float(ti_total_score)
    row["threat_intel_top_category"] = top_cat
    row["threat_intel_top_confidence"] = top_conf

    return row


# ======================================================================
# Training
# ======================================================================


def train_model(labels_qs) -> dict[str, Any]:
    """
    Train on the given TrainingLabel queryset. Returns a metadata dict:
      {status: "trained"|"insufficient_data",
       n_train, n_test, n_total,
       accuracy, auc, per_class_counts,
       feature_importances,
       model_version, trained_at}
    """
    from apps.feedback.models import TrainingLabel

    # Filter to rows that have a usable label.
    usable = labels_qs.filter(
        label__in=[TrainingLabel.LABEL_APPROVE, TrainingLabel.LABEL_DENY,
                   TrainingLabel.LABEL_BAD,     TrainingLabel.LABEL_GOOD],
    )
    total = usable.count()
    counts: dict[str, int] = {}
    for lbl in ("approve", "deny", "bad", "good"):
        counts[lbl] = usable.filter(label=lbl).count()

    # Binarize: bad = {deny, bad}, good = {approve, good}
    bad_count = counts["deny"] + counts["bad"]
    good_count = counts["approve"] + counts["good"]

    meta: dict[str, Any] = {
        "per_class_counts": counts,
        "bad_count": bad_count,
        "good_count": good_count,
        "total_labels": total,
    }

    if total < MIN_LABELS_TOTAL or bad_count < MIN_LABELS_PER_CLASS or good_count < MIN_LABELS_PER_CLASS:
        meta["status"] = "insufficient_data"
        meta["reason"] = (
            f"Need ≥{MIN_LABELS_TOTAL} total labels (have {total}) and ≥{MIN_LABELS_PER_CLASS} "
            f"each of bad/good (have bad={bad_count}, good={good_count})."
        )
        return meta

    # Heavy imports only once we know we'll train.
    try:
        import numpy as np
        import pandas as pd
        import joblib
        from sklearn.compose import ColumnTransformer
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.metrics import accuracy_score, roc_auc_score
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import OneHotEncoder
    except ImportError as exc:
        meta["status"] = "missing_dependencies"
        meta["reason"] = f"Install training deps: pip install scikit-learn pandas joblib numpy ({exc})"
        return meta

    rows: list[dict] = []
    labels: list[int] = []
    for row in usable.iterator(chunk_size=500):
        feat = vectorize_features(row.features or {})
        rows.append(feat)
        labels.append(1 if row.label in (TrainingLabel.LABEL_DENY, TrainingLabel.LABEL_BAD) else 0)

    X = pd.DataFrame(rows)
    y = np.array(labels)

    categorical = [c for c in CATEGORICAL_FEATURE_NAMES if c in X.columns]
    numeric = [c for c in X.columns if c not in categorical]

    preprocessor = ColumnTransformer([
        ("num", "passthrough", numeric),
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical),
    ])
    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("clf", GradientBoostingClassifier(n_estimators=200, max_depth=4, random_state=42)),
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    pipeline.fit(X_train, y_train)

    pred = pipeline.predict(X_test)
    proba = pipeline.predict_proba(X_test)[:, 1]
    acc = float(accuracy_score(y_test, pred))
    try:
        auc = float(roc_auc_score(y_test, proba))
    except Exception:
        auc = None

    # Persist
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)

    # Feature importances — only works for the concrete classifier step.
    try:
        importances = pipeline.named_steps["clf"].feature_importances_.tolist()
        ohe = pipeline.named_steps["preprocessor"].named_transformers_["cat"]
        cat_features = list(ohe.get_feature_names_out(categorical)) if categorical else []
        feature_names = numeric + cat_features
        top_features = sorted(
            zip(feature_names, importances), key=lambda x: -x[1]
        )[:20]
    except Exception:
        top_features = []

    import datetime as _dt
    meta.update({
        "status": "trained",
        "n_train": len(X_train),
        "n_test": len(X_test),
        "accuracy": acc,
        "auc": auc,
        "feature_importances": top_features,
        "model_version": _dt.datetime.utcnow().isoformat() + "Z",
        "model_path": str(MODEL_PATH),
    })
    with open(METADATA_PATH, "w") as f:
        json.dump(meta, f, indent=2, default=str)
    return meta


# ======================================================================
# Inference — hot-reloading cached model
# ======================================================================


_MODEL_CACHE: dict = {"mtime": None, "pipeline": None, "meta": None}
_MODEL_LOCK = threading.Lock()


def _load_model():
    if not MODEL_PATH.exists():
        return None, None
    mtime = os.path.getmtime(MODEL_PATH)
    with _MODEL_LOCK:
        if _MODEL_CACHE["mtime"] == mtime and _MODEL_CACHE["pipeline"] is not None:
            return _MODEL_CACHE["pipeline"], _MODEL_CACHE["meta"]
        try:
            import joblib
            pipeline = joblib.load(MODEL_PATH)
        except Exception:
            logger.exception("Failed to load fraud model at %s", MODEL_PATH)
            return None, None
        meta = None
        try:
            with open(METADATA_PATH) as f:
                meta = json.load(f)
        except Exception:
            pass
        _MODEL_CACHE["mtime"] = mtime
        _MODEL_CACHE["pipeline"] = pipeline
        _MODEL_CACHE["meta"] = meta
        return pipeline, meta


def predict_fraud_probability(features: dict[str, Any]) -> float | None:
    """
    Returns p(bad) in [0, 1] for the given snapshot, or None if no model trained yet.
    """
    pipeline, _ = _load_model()
    if pipeline is None:
        return None
    try:
        import pandas as pd
        row = vectorize_features(features)
        X = pd.DataFrame([row])
        proba = pipeline.predict_proba(X)[:, 1][0]
        return float(proba)
    except Exception:
        logger.exception("ML inference failed")
        return None


def get_model_metadata() -> dict | None:
    """Metadata of the currently-loaded model, or None if no model exists."""
    _, meta = _load_model()
    return meta


def readiness_report() -> dict:
    """
    Return training-readiness stats — how many labels exist, class balance,
    whether a model is already trained, recent predictions count.
    """
    from apps.feedback.models import TrainingLabel
    total = TrainingLabel.objects.count()
    per_label = dict(
        TrainingLabel.objects.values_list("label").annotate(n=__import__("django.db.models", fromlist=["Count"]).Count("id"))
    ) if total else {}
    bad = per_label.get("deny", 0) + per_label.get("bad", 0)
    good = per_label.get("approve", 0) + per_label.get("good", 0)

    return {
        "total": total,
        "per_label": per_label,
        "bad": bad,
        "good": good,
        "min_required": MIN_LABELS_TOTAL,
        "min_per_class": MIN_LABELS_PER_CLASS,
        "ready_to_train": (
            total >= MIN_LABELS_TOTAL
            and bad >= MIN_LABELS_PER_CLASS
            and good >= MIN_LABELS_PER_CLASS
        ),
        "current_model": get_model_metadata(),
    }
