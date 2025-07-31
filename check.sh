#!/bin/bash
# RHEL10 システム確認スクリプト

echo "=== RHEL10 システム状態確認 ==="
echo "実行日時: $(date)"
echo

# OS情報
echo "=== OS情報 ==="
cat /etc/redhat-release
uname -r
echo

# パッケージ確認
PACKAGES_TO_CHECK=(
    "dnf" "podman" "git" "python3.12" "java-17-openjdk-devel" 
    "httpd" "nginx" "postgresql-server" "htop" "fail2ban"
)

echo "=== 重要パッケージ確認 ==="
for pkg in "${PACKAGES_TO_CHECK[@]}"; do
    if rpm -q "$pkg" > /dev/null 2>&1; then
        echo "✓ $pkg がインストールされています"
    else
        echo "✗ $pkg がインストールされていません"
    fi
done
echo

# サービス状態
echo "=== 重要サービス状態 ==="
SERVICES=("sshd" "firewalld" "chronyd" "httpd" "postgresql")
for service in "${SERVICES[@]}"; do
    status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
    echo "$service: $status"
done
echo

# セキュリティ状態
echo "=== セキュリティ状態 ==="
echo "SELinux: $(getenforce)"
echo "Firewalld: $(systemctl is-active firewalld)"
echo

# ネットワーク確認
echo "=== ネットワーク確認 ==="
ip addr show | grep -E "inet.*eth0|inet.*enp" | head -1
ss -tuln | grep -E ":22|:80|:443|:3306|:5432" | head -5
echo

echo "=== 確認完了 ==="