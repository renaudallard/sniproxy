#!/bin/sh

VERSION=0.11.1

SOURCE_DIR=$(dirname $0)
GIT_DIR=${SOURCE_DIR}/.git

cd ${SOURCE_DIR}

if [ -d ${GIT_DIR} ]; then
    GIT_VERSION=$(git describe --tags 2>/dev/null)
    if [ "x" != "x${GIT_VERSION}" ]; then
        if echo ${GIT_VERSION} | grep -q '-'; then
            REV=$(echo ${GIT_VERSION} | cut -d- -f2)
            REF=$(echo ${GIT_VERSION} | cut -d- -f3)

            # Use the hardcoded VERSION as base, not the old tag
            VERSION=${VERSION}+git.${REV}.${REF}
        else
            # Release version (e.g. 0.3.5)
            VERSION=${GIT_VERSION}
            DEBIAN_VERSION=${VERSION}
            SPEC_VERSION=${VERSION}
        fi
    fi
fi

# Portable in-place sed (macOS sed -i requires '' argument)
sedi() {
    if sed --version >/dev/null 2>&1; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

# Update Autoconf with new version
sedi "s/^\(AC_INIT(\[sniproxy\], \[\)[^]]*\(.\+\)$/\1${VERSION}\2/" ${SOURCE_DIR}/configure.ac

# Update redhat/sniproxy.spec with new version
sedi "s/^Version:[[:space:]]\{1,\}[^ ]\{1,\}/Version: ${VERSION}/" ${SOURCE_DIR}/redhat/sniproxy.spec

# Update debian/changelog with new version when debchange is available
if command -v debchange >/dev/null 2>&1; then
    debchange --newversion ${VERSION} "New git revision"
else
    echo "debchange not found; skipping debian/changelog update" >&2
fi
