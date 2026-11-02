#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

staged=$(git diff --cached --name-only --diff-filter=ACMR)
[ -n "$staged" ] || exit 0

# Re-staging a formatted file would also capture its unstaged edits. Refuse that
# ambiguous case so a commit cannot absorb another change by accident.
for file in $staged; do
    if ! git diff --quiet -- "$file"; then
        echo "format-staged: $file has unstaged edits" >&2
        exit 1
    fi
done

for file in $staged; do
    [ -f "$file" ] || continue
    case "$file" in
        *.c|*.h|*.java)
            uvx --from clang-format==22.1.8 clang-format -i "$file"
            ;;
        *.py)
            uvx --from ruff==0.17.1 ruff format \
                --config bindings/python/pyproject.toml "$file"
            ;;
        *.rs)
            # A crate root normally makes rustfmt recurse into every module.
            # Keep the hook scoped to the file that is actually staged.
            rustfmt --edition 2024 --config skip_children=true "$file"
            ;;
        bindings/dotnet/*.cs|bindings/dotnet/**/*.cs)
            dotnet format whitespace bindings/dotnet/Dfc.sln --include "$file"
            ;;
        examples/dotnet/*.cs)
            dotnet format whitespace examples/dotnet/Dfc.TransceiveExample.csproj --include "$file"
            ;;
    esac
    git add -- "$file"
done
