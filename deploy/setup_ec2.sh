#!/usr/bin/env bash
# 메디가이드 EC2 설치 스크립트 (Ubuntu 22.04 / 24.04, t3.medium 이상 권장)
# 사용: 저장소를 받은 뒤 그 폴더에서  sudo bash deploy/setup_ec2.sh
set -euo pipefail
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_USER="${SUDO_USER:-ubuntu}"

echo "[1/7] 시스템 패키지"
apt-get update -y
apt-get install -y python3 python3-venv python3-pip git nginx fonts-nanum curl unzip wget

echo "[2/7] PDF 변환용 Chrome (헤드리스)"
if ! command -v google-chrome >/dev/null 2>&1; then
  wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
  apt-get install -y /tmp/chrome.deb || apt-get -f install -y
fi

echo "[3/7] 파이썬 가상환경과 패키지"
sudo -u "$APP_USER" python3 -m venv "$APP_DIR/.venv"
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install -q --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "[4/7] OpenGrep (정적분석 엔진, 오픈소스)"
if ! command -v opengrep >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | sudo -u "$APP_USER" bash || \
    echo "  OpenGrep 설치 실패 — Semgrep(requirements.txt)으로 대신 동작합니다"
  [ -f "/home/$APP_USER/.opengrep/cli/latest/opengrep" ] && ln -sf "/home/$APP_USER/.opengrep/cli/latest/opengrep" /usr/local/bin/opengrep || true
fi

echo "[5/7] 환경설정 (.env)"
if [ ! -f "$APP_DIR/.env" ]; then
  cp "$APP_DIR/deploy/env.example" "$APP_DIR/.env"
  sed -i "s/^MG_SECRET=.*/MG_SECRET=$(openssl rand -hex 32)/" "$APP_DIR/.env"
  chown "$APP_USER":"$APP_USER" "$APP_DIR/.env"; chmod 600 "$APP_DIR/.env"
  echo "  $APP_DIR/.env 를 열어 MG_BEDROCK_MODEL·관리자 비밀번호를 채우세요"
fi

echo "[6/7] 검색 색인과 시연 데이터"
cd "$APP_DIR"
sudo -u "$APP_USER" bash -c "set -a; . ./.env; set +a; .venv/bin/python scripts/build_index.py && .venv/bin/python -X utf8 scripts/seed_demo.py"

echo "[7/7] 서비스 등록 (systemd + nginx)"
sed "s#__APP_DIR__#$APP_DIR#g; s#__APP_USER__#$APP_USER#g" deploy/mediguide.service > /etc/systemd/system/mediguide.service
cp deploy/nginx.conf /etc/nginx/sites-available/mediguide
ln -sf /etc/nginx/sites-available/mediguide /etc/nginx/sites-enabled/mediguide
rm -f /etc/nginx/sites-enabled/default
systemctl daemon-reload
systemctl enable --now mediguide
nginx -t && systemctl restart nginx
echo "완료: http://<EC2 공인 IP>/  (상태: systemctl status mediguide, 로그: journalctl -u mediguide -f)"
