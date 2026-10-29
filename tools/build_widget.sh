#!/bin/sh
# Собирает архив виджета для загрузки в OkoStore: dist/redsms-widget-<version>.zip
set -eu
cd "$(dirname "$0")/.."

if grep -q "sms.example.com\|CHANGE_ME" widget/config.json; then
    echo "widget/config.json: замените sms.example.com и author (CHANGE_ME) перед сборкой" >&2
    exit 1
fi
python3 -c "import json; json.load(open('widget/config.json', encoding='utf-8'))"
[ -f widget/logo.png ] || echo "предупреждение: нет widget/logo.png" >&2

version=$(python3 -c "import json; print(json.load(open('widget/config.json'))['version'])")
mkdir -p dist
rm -f "dist/redsms-widget-$version.zip"
(cd widget && zip -qrX "../dist/redsms-widget-$version.zip" . -x '.*')
echo "dist/redsms-widget-$version.zip"
