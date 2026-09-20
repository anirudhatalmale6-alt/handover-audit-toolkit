#!/bin/sh
# Run the whole audit end to end.
#
#   ./run_all.sh sa.json you@domain.com [partner@domain.com] [YYYY-MM-DD handover]
#
# Set FB_TOKEN in the environment for the Facebook leg. If it is unset that
# leg is skipped and the report says so, rather than reporting a clean
# Facebook history that was never actually looked at.

set -e

KEY="$1"
ADMIN="$2"
PARTNER="$3"
HANDOVER="$4"
OUT="${OUT:-out}"
DAYS_GOOGLE="${DAYS_GOOGLE:-180}"
DAYS_FB="${DAYS_FB:-90}"

if [ -z "$KEY" ] || [ -z "$ADMIN" ]; then
    echo "usage: $0 <service-account.json> <admin@domain.com> [partner@domain.com] [handover YYYY-MM-DD]" >&2
    exit 2
fi

echo "==> Google Workspace"
python3 -m audittk.gw_export --key "$KEY" --admin "$ADMIN" \
    --out "$OUT/google" --days "$DAYS_GOOGLE"

echo "==> GCP"
# A tenant with no GCP projects is normal; do not abort the whole run for it.
python3 -m audittk.gcp_export --key "$KEY" --out "$OUT/gcp" --days "$DAYS_GOOGLE" \
    || echo "    GCP leg returned non-zero - see $OUT/gcp/_collection_metadata.json"

if [ -n "$FB_TOKEN" ]; then
    echo "==> Meta Business Manager"
    python3 -m audittk.fb_export --out "$OUT/facebook" --days "$DAYS_FB" \
        || echo "    Facebook leg returned non-zero - see $OUT/facebook/_collection_metadata.json"
else
    echo "==> Meta Business Manager SKIPPED (FB_TOKEN not set)"
fi

echo "==> Report"
ARGS="--dir $OUT"
[ -n "$PARTNER" ] && ARGS="$ARGS --partner $PARTNER"
[ -n "$HANDOVER" ] && ARGS="$ARGS --handover $HANDOVER"
# shellcheck disable=SC2086
python3 -m audittk.analyze $ARGS

echo "==> Manifest"
python3 -m audittk.manifest --dir "$OUT"

echo
echo "Done. Read $OUT/REPORT.md"
echo "Keep the root hash above somewhere separate from the archive."
