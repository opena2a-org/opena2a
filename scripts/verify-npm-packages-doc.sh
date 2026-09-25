#!/usr/bin/env bash
# Runs the blocks in docs/verifying-npm-packages.md verbatim, per package, with the controls the
# verification record requires. Usage: scripts/verify-npm-packages-doc.sh <doc.md> <out-dir> [latest|all]
#   latest: G1 plus the controls (T, I, C, V, U)      all: adds G2 (every attested version)
# Each cell runs the extracted block text unchanged in a fresh empty directory. Controls act only
# through PATH shims (npm, curl) or the documented environment override; cell I is the one text
# mutation, and the runner asserts it changes exactly one token. Needs: bash, npm, jq, openssl,
# tar, curl, cosign >= 3.0.6 on PATH. Writes <out-dir>/cells.tsv and one log per cell.
set -u
DOC=$1; OUT=$2; MODE=${3:-latest}
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd); DOC=$(cd "$(dirname "$DOC")" && pwd)/$(basename "$DOC")
SHELL_UNDER_TEST=${SHELL_UNDER_TEST:-bash}
REAL_NPM=$(command -v npm); REAL_CURL=$(command -v curl)
TSV=$OUT/cells.tsv; printf 'package\tversion\tcell\texpect\texit\tlast_line\tresult\n' > "$TSV"
FAILS=0

# pkg | env var | first attested version | tarball prefix | attestation path
PKGS='hackmyagent|HACKMYAGENT_VERSION|0.18.2|hackmyagent|hackmyagent
secretless-ai|SECRETLESS_AI_VERSION|0.15.1|secretless-ai|secretless-ai
opena2a-cli|OPENA2A_CLI_VERSION|0.8.24|opena2a-cli|opena2a-cli
@opena2a/aim-core|AIM_CORE_VERSION|0.2.0|opena2a-aim-core|@opena2a%2faim-core'

extract() { # the first fenced block after the heading whose text is exactly the package name
  awk -v pkg="$1" '
    /^## / { h=$0; sub(/^## +/,"",h); gsub(/`/,"",h); insec=(h==pkg); next }
    insec && /^```/ { if (!inblk) { inblk=1; next } else { exit } }
    insec && inblk { print }' "$DOC"
}

run_cell() { # pkg version cell expect(ok|fail:<substring>) blockfile [VAR=value ...]
  local pkg=$1 ver=$2 cell=$3 expect=$4 block=$5; shift 5
  local d log rc last res; d=$(mktemp -d "${TMPDIR:-/tmp}/vcell.XXXXXX"); mkdir -p "$d/home"
  log=$OUT/$(echo "$pkg" | tr '/@' '__')--$cell--$ver.log
  ( cd "$d" && env HOME="$d/home" npm_config_cache="$d/home/.npm" npm_config_update_notifier=false "$@" \
      "$SHELL_UNDER_TEST" "$block" ) > "$log" 2>&1
  rc=$?; last=$(grep -v '^[[:space:]]*$' "$log" | tail -1 | tr '\t' ' ' | cut -c1-160)
  case $expect in
    ok) if [ $rc -eq 0 ] && [ "$last" = "Verified OK" ]; then res=PASS; else res=FAIL; fi ;;
    fail:*) want=${expect#fail:}
       if [ $rc -ne 0 ] && grep -qF -- "$want" "$log" && ! grep -q '^Verified OK$' "$log"; then res=PASS; else res=FAIL; fi ;;
  esac
  [ $res = FAIL ] && FAILS=$((FAILS+1))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pkg" "$ver" "$cell" "$expect" "$rc" "$last" "$res" >> "$TSV"
  rm -rf "$d"
}

SHIMS=$OUT/.shims; mkdir -p "$SHIMS"
mkshim_tamper() { # npm pack, then append one byte to the produced tarball
  mkdir -p "$SHIMS/tamper"; cat > "$SHIMS/tamper/npm" <<EOF
#!/usr/bin/env bash
"$REAL_NPM" "\$@"; rc=\$?
if [ "\$1" = pack ]; then for f in ./*.tgz; do printf 'x' >> "\$f"; done; fi
exit \$rc
EOF
  chmod +x "$SHIMS/tamper/npm"; }
mkshim_swap() { # dir name; serve SRC_SPEC's genuine tarball and bundle under the requested name
  local dir=$SHIMS/$1; mkdir -p "$dir"; cat > "$dir/npm" <<EOF
#!/usr/bin/env bash
if [ "\$1" = pack ]; then
  out=\$("$REAL_NPM" pack "\$SWAP_SRC_SPEC" --silent | tail -1); mv "\$out" "\$SWAP_DEST_TGZ"; exit 0
fi
exec "$REAL_NPM" "\$@"
EOF
  cat > "$dir/curl" <<EOF
#!/usr/bin/env bash
exec "$REAL_CURL" -sSf "https://registry.npmjs.org/-/npm/v1/attestations/\$SWAP_SRC_ATT"
EOF
  chmod +x "$dir/npm" "$dir/curl"; }
mkshim_tamper; mkshim_swap swap

while IFS='|' read -r pkg var first tgzp att; do
  blk=$OUT/.block-$(echo "$pkg" | tr '/@' '__').sh; extract "$pkg" > "$blk"
  [ -s "$blk" ] || { echo "no block found for $pkg" >&2; FAILS=$((FAILS+1)); continue; }
  latest=$("$REAL_NPM" view "$pkg" version)
  # G1: latest, block as written
  run_cell "$pkg" "$latest" G1 ok "$blk"
  # G2: every published version from the first attested one
  if [ "$MODE" = all ]; then
    g2=0
    for v in $("$REAL_NPM" view "$pkg" versions --json | jq -r '.[]' | awk -v f="$first" '
        function cmp(a,b,  x,y,i){split(a,x,".");split(b,y,".");for(i=1;i<=3;i++){if(x[i]+0<y[i]+0)return -1;if(x[i]+0>y[i]+0)return 1}return 0}
        $0 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ && cmp($0,f)>=0'); do
      run_cell "$pkg" "$v" G2 ok "$blk" "$var=$v"; g2=$((g2+1))
    done
    # an empty version list (a failed lookup) is a failure, never a pass with no cells
    [ $g2 -gt 0 ] || { echo "no G2 versions listed for $pkg" >&2; FAILS=$((FAILS+1)); }
  fi
  # T: one byte appended to the packed tarball
  run_cell "$pkg" "$latest" T "fail:provided artifact digest does not match" "$blk" PATH="$SHIMS/tamper:$PATH"
  # I: the identity changed by exactly one token (the repo name)
  mut=$OUT/.mut-$(echo "$pkg" | tr '/@' '__').sh
  case $pkg in
    hackmyagent)       sed 's#opena2a-org/hackmyagent/#opena2a-org/secretless-ai/#' "$blk" > "$mut" ;;
    secretless-ai)     sed 's#opena2a-org/secretless-ai/#opena2a-org/hackmyagent/#' "$blk" > "$mut" ;;
    *)                 sed 's#opena2a-org/opena2a/#opena2a-org/hackmyagent/#' "$blk" > "$mut" ;;
  esac
  ntok=$(diff <(tr -s ' /' '\n' < "$blk") <(tr -s ' /' '\n' < "$mut") | grep -c '^[<>]')
  if [ "$ntok" -ne 2 ]; then echo "cell I for $pkg changed $ntok token lines, want exactly one token" >&2; FAILS=$((FAILS+1)); fi
  run_cell "$pkg" "$latest" I "fail:no matching CertificateIdentity" "$mut"
  # C: another genuine tarball and bundle served under the requested name
  case $pkg in
    hackmyagent|secretless-ai) prev=$("$REAL_NPM" view "$pkg" versions --json | jq -r '.[]' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | tail -2 | head -1)
       src="$pkg@$prev"; srcatt="$att@$prev"; cv=$latest ;;
    opena2a-cli) src='@opena2a/shared@0.1.2'; srcatt='@opena2a%2fshared@0.1.2'; cv=0.8.24 ;;
    @opena2a/aim-core) src="opena2a-cli@0.10.13"; srcatt="opena2a-cli@0.10.13"; cv=$latest ;;
  esac
  run_cell "$pkg" "$cv" C "fail:tarball check failed" "$blk" PATH="$SHIMS/swap:$PATH" "$var=$cv" SWAP_SRC_SPEC="$src" SWAP_SRC_ATT="$srcatt" SWAP_DEST_TGZ="$tgzp-$cv.tgz"
  # V: an injected version string (regexp block only)
  [ "$pkg" = opena2a-cli ] && run_cell "$pkg" 'inj' V "fail:not a release version" "$blk" "$var=0.10.13\$|.*"
  # U: a version from before provenance began
  case $pkg in opena2a-cli) u=0.8.23 ;; hackmyagent) u=0.17.11 ;; *) u= ;; esac
  [ -n "$u" ] && run_cell "$pkg" "$u" U "fail:curl:" "$blk" "$var=$u"
done <<< "$PKGS"

echo "cells: $(($(wc -l < "$TSV")-1)), failures: $FAILS (table: $TSV)"
[ $FAILS -eq 0 ]
