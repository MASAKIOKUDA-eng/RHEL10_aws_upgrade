#!/bin/bash
# RHEL9 完全セットアップスクリプト

set -euo pipefail

# カラー定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# root権限チェック
if [[ $EUID -ne 0 ]]; then
    log_error "このスクリプトはroot権限で実行してください: sudo $0"
    exit 1
fi

# システム情報表示
log_info "システム情報:"
cat /etc/redhat-release
echo

# システム更新
log_info "システムを更新中..."
dnf update -y

# RHEL9用EPEL設定
log_info "RHEL9用EPELリポジトリを設定中..."

# CRBリポジトリ有効化（複数の方法を試行）
log_info "CodeReady Builderリポジトリを有効化中..."
if command -v subscription-manager &> /dev/null; then
    subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms || \
    log_warn "subscription-managerでのCRB有効化に失敗"
fi

# 代替方法でCRB有効化
dnf config-manager --set-enabled crb 2>/dev/null || \
log_warn "dnf config-managerでのCRB有効化に失敗"

# RHEL9用EPEL インストール
log_info "RHEL9用EPELをインストール中..."
dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm

# パッケージ定義
BASIC_PACKAGES=(
    "vim-enhanced" "wget" "curl" "git" "htop" "tree" "unzip" 
    "tar" "rsync" "bash-completion" "bind-utils" "net-tools"
)

DEVELOPMENT_PACKAGES=(
    "gcc" "gcc-c++" "make" "cmake" "gdb" "valgrind"
    "python3.9" "python3.9-pip" "python3.9-devel"
    "java-17-openjdk-devel"
)

SECURITY_PACKAGES=(
    "fail2ban" "aide" "firewalld"
)

MONITORING_PACKAGES=(
    "iotop" "nethogs" "tcpdump" "chrony"
)

# 基本パッケージインストール
log_info "基本パッケージをインストール中..."
dnf install -y "${BASIC_PACKAGES[@]}"

# 開発ツールインストール
log_info "開発ツールをインストール中..."
dnf groupinstall -y "Development Tools"
dnf install -y "${DEVELOPMENT_PACKAGES[@]}"

# コンテナツール（RHEL9標準）
log_info "コンテナツールを設定中..."
dnf install -y podman buildah skopeo podman-docker

# セキュリティツール
log_info "セキュリティツールを設定中..."
dnf install -y "${SECURITY_PACKAGES[@]}"

# 監視ツール
log_info "監視ツールを設定中..."
dnf install -y "${MONITORING_PACKAGES[@]}"

# ファイアウォール設定
log_info "ファイアウォールを設定中..."
systemctl enable --now firewalld
firewall-cmd --permanent --add-service=ssh
firewall-cmd --reload

# サービス有効化
log_info "基本サービスを有効化中..."
systemctl enable --now chronyd

log_info "RHEL9 セットアップが完了しました！"
log_info

# インストール確認
log_info "インストールされたパッケージの確認:"
echo "Python: $(python3.9 --version 2>/dev/null || echo 'Not installed')"
echo "Java: $(java -version 2>&1 | head -1 || echo 'Not installed')"
echo "Git: $(git --version 2>/dev/null || echo 'Not installed')"
echo "Podman: $(podman --version 2>/dev/null || echo 'Not installed')"