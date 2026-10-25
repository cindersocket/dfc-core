#!/usr/bin/env bash
set -euo pipefail

root=${1:?usage: publish-maven-artifacts.sh ARTIFACT_DIRECTORY}
version=$(python3 -c 'import json; print(json.load(open("release-artifacts.json"))["version"])')
: "${MAVEN_CENTRAL_USERNAME:?Maven Central username is required}"
: "${MAVEN_CENTRAL_PASSWORD:?Maven Central password is required}"
: "${MAVEN_GPG_PRIVATE_KEY:?Maven signing key is required}"

java_exists=false
android_exists=false
curl --fail --silent --show-error \
    "https://repo1.maven.org/maven2/com/cindersocket/dfc-core/$version/dfc-core-$version.pom" \
    >/dev/null && java_exists=true
curl --fail --silent --show-error \
    "https://repo1.maven.org/maven2/com/cindersocket/dfc-core-android/$version/dfc-core-android-$version.pom" \
    >/dev/null && android_exists=true
if [[ "$java_exists" == true && "$android_exists" == true ]]; then
    echo "Maven artifacts $version are already published"
    exit 0
fi
if [[ "$java_exists" != "$android_exists" ]]; then
    echo "Maven Central contains an incomplete $version release" >&2
    exit 1
fi

staging=$(mktemp -d)
key_file=$(mktemp)
trap 'rm -rf "$staging" "$key_file"' EXIT
printf '%s' "$MAVEN_GPG_PRIVATE_KEY" > "$key_file"
gpg --batch --import "$key_file"

install_artifact() {
    local group_path=$1 artifact=$2 source=$3 name=$4
    local destination="$staging/$group_path/$artifact/$version"
    mkdir -p "$destination"
    cp "$source" "$destination/$name"
}

java_dir=$(find "$root" -type f -name "dfc-core-$version.jar" -exec dirname {} \; | head -1)
for suffix in .jar -sources.jar -javadoc.jar .pom; do
    install_artifact com/cindersocket dfc-core \
        "$java_dir/dfc-core-$version$suffix" "dfc-core-$version$suffix"
done

while IFS= read -r jar; do
    install_artifact com/cindersocket dfc-core "$jar" "$(basename "$jar")"
done < <(find "$root" -type f -name "dfc-core-$version-*.jar" \
    ! -name '*-sources.jar' ! -name '*-javadoc.jar' -print)

android=$(find "$root" -type f -name "dfc-core-android-$version.aar" -print -quit)
android_dir=$(dirname "$android")
for suffix in .aar -sources.jar -javadoc.jar .pom; do
    file="$android_dir/dfc-core-android-$version$suffix"
    install_artifact com/cindersocket dfc-core-android "$file" "$(basename "$file")"
done

mapfile -d '' files < <(find "$staging" -type f -print0)
for file in "${files[@]}"; do
    gpg --batch --yes --pinentry-mode loopback \
        --passphrase "${MAVEN_GPG_PASSPHRASE:-}" --armor --detach-sign "$file"
    md5sum "$file" | cut -d' ' -f1 > "$file.md5"
    sha1sum "$file" | cut -d' ' -f1 > "$file.sha1"
    sha256sum "$file" | cut -d' ' -f1 > "$file.sha256"
    sha512sum "$file" | cut -d' ' -f1 > "$file.sha512"
done

(cd "$staging" && zip -qr "$OLDPWD/central-bundle.zip" .)
token=$(printf '%s:%s' "$MAVEN_CENTRAL_USERNAME" "$MAVEN_CENTRAL_PASSWORD" | base64 | tr -d '\n')
curl --fail-with-body --header "Authorization: Bearer $token" \
    --form bundle=@central-bundle.zip \
    'https://central.sonatype.com/api/v1/publisher/upload?publishingType=AUTOMATIC'
