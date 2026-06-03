#!/usr/bin/env bash
# Run soapbar's live integration tests (-m live) against real services, locally.
#
# Why local: the NF-e ICP-Brasil certificate is a private key that should never
# be uploaded to shared CI. Run these on your own machine so the key stays here.
#
# VIES needs nothing — it uses the EC deterministic *test* service.
# WITSML and NF-e need credentials; set them in a gitignored .env.live (this
# script sources it) or in your shell. Tests whose inputs are absent skip.
#
#   # .env.live  (gitignored — never commit; use a HOMOLOGAÇÃO cert, not prod)
#   WITSML_URL=https://host/witsml/services/store
#   WITSML_USER=...
#   WITSML_PASSWORD=...
#   NFE_PFX=/abs/path/to/homolog-cert.pfx
#   NFE_PFX_PASSWORD=...
#   NFE_STATUS_URL=https://homologacao.sefaz.uf/ws/NFeStatusServico4
#   NFE_UF=31
#
# Usage:  scripts/live.sh                 # all live tests (skips uncredentialed)
#         scripts/live.sh tests/test_contrib_vies.py    # just one
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env.live ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env.live
  set +a
fi
exec uv run pytest -m live -v --no-cov "$@"
