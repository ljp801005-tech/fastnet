#!/usr/bin/env bash
# 一键交叉编译三端产物到 dist/
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(grep -oE 'version = "[^"]+"' main.go | head -1 | cut -d'"' -f2)
echo "==> FastNet v${VERSION}"

mkdir -p dist
rm -rf dist/*

build() { # build <GOOS> <GOARCH> <输出文件>
  GOOS="$1" GOARCH="$2" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o "$3" .
}

echo "==> Windows amd64"
build windows amd64 dist/fastnet.exe

echo "==> macOS arm64 / amd64"
build darwin arm64 dist/fastnet-arm64
build darwin amd64 dist/fastnet-amd64
lipo -create -output dist/fastnet dist/fastnet-arm64 dist/fastnet-amd64
rm -f dist/fastnet-arm64 dist/fastnet-amd64
chmod +x dist/fastnet

echo "==> 组装发布包"
mkdir -p dist/Win dist/mac
mv dist/fastnet.exe dist/Win/
cp dist/fastnet dist/mac/
cp mobile/FastNet-Android.html dist/Win/FastNet-Android.html
cp mobile/FastNet-Android.html dist/mac/FastNet-Android.html
chmod +x dist/mac/fastnet

# mac 双击启动器
cat > dist/mac/启动FastNet.command <<'LAUNCHER'
#!/bin/bash
# FastNet 本地网络体检 · macOS 启动器
# 双击运行；如提示「无法验证开发者」，请右键 → 打开
cd "$(dirname "$0")" || exit 1
xattr -dr com.apple.quarantine . >/dev/null 2>&1
chmod +x ./fastnet >/dev/null 2>&1
if [ ! -x ./fastnet ]; then
  echo "找不到 fastnet 可执行文件，请确认它和本文件在同一目录。"
  read -n 1 -s -r -p "按任意键关闭..."
  exit 1
fi
clear
./fastnet
echo
echo "已退出 FastNet。"
LAUNCHER
chmod +x dist/mac/启动FastNet.command

( cd dist && zip -qr "FastNet-Win-v${VERSION}.zip" Win && zip -qr "FastNet-mac-v${VERSION}.zip" mac )
cp mobile/FastNet-Android.html "dist/FastNet-Android-v${VERSION}.html"

echo
echo "完成，产物在 dist/："
ls -lh dist
