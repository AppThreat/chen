#!/usr/bin/env bash
pushd $(dirname $0)
composer update --no-progress --prefer-dist --ignore-platform-reqs
popd
export PHP_PARSER_BIN="$(dirname $0)/vendor/bin/php-parse"
