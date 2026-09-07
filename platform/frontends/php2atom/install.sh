#!/usr/bin/env bash
# Installs the PHP parser php2atom shells out to, at exactly the version composer.lock pins.
#
# The lock is authoritative: `install` (not `update`) so the version is reproducible, preceded by
# `validate --check-lock` because `install` only warns on a stale lock and then proceeds. Keep the
# pinned nikic/php-parser version in step with the one atom-parsetools vendors - that is the
# generator chen meets at runtime.
pushd $(dirname $0)
composer validate --no-check-publish --no-check-all --check-lock
composer install --no-progress --prefer-dist --ignore-platform-reqs
popd
export PHP_PARSER_BIN="$(dirname $0)/vendor/bin/php-parse"
