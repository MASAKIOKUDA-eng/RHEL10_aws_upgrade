#!/bin/bash
# RHEL10移行詳細確認スクリプト
# 実行方法: sudo ./rhel10_detailed_check.sh [--report-html] [--export-json]

set -euo pipefail

# カラー定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# グローバル変数
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/tmp/rhel10_check_$TIMESTAMP"
LOG_FILE="$REPORT_DIR/detailed_check.log"
JSON_OUTPUT="$REPORT_DIR/system_info.json"
HTML_REPORT="$REPORT_DIR/system_report.html"
CSV_OUTPUT="$REPORT_DIR/packages_info.csv"

# 引数解析
GENERATE_HTML=false
EXPORT_JSON=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --report-html)
            GENERATE_HTML=true
            shift
            ;;
        --export-json)
            EXPORT_JSON=true
            shift
            ;;
        -h|--help)
            echo "使用方法: $0 [--report-html] [--export-json]"
            echo "  --report-html  HTML形式のレポートを生成"
            echo "  --export-json  JSON形式でデータをエクスポート"
            exit 0
            ;;
        *)
            echo "不明なオプション: $1"
            exit 1
            ;;
    esac
done

# ディレクトリ作成
mkdir -p "$REPORT_DIR"

# ログ関数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
log_debug() { echo -e "${CYAN}[DEBUG]${NC} $1" | tee -a "$LOG_FILE"; }

# JSON出力用変数初期化
if [ "$EXPORT_JSON" = true ]; then
    echo '{' > "$JSON_OUTPUT"
    echo '  "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",' >> "$JSON_OUTPUT"
    echo '  "hostname": "'$(hostname)'",' >> "$JSON_OUTPUT"
fi

# JSON書き込み関数
json_add() {
    if [ "$EXPORT_JSON" = true ]; then
        echo "  \"$1\": $2," >> "$JSON_OUTPUT"
    fi
}

# =============================================================================
# システム基本情報収集
# =============================================================================
collect_system_info() {
    log_info "システム基本情報を収集中..."
    
    local info_file="$REPORT_DIR/system_basic_info.txt"
    
    {
        echo "=== システム基本情報 ==="
        echo "収集日時: $(date)"
        echo "ホスト名: $(hostname)"
        echo "FQDN: $(hostname -f 2>/dev/null || echo 'N/A')"
        echo "稼働時間: $(uptime)"
        echo "現在のユーザー: $(whoami)"
        echo "作業ディレクトリ: $(pwd)"
        echo
        
        echo "=== OS情報 ==="
        echo "OS: $(cat /etc/redhat-release)"
        echo "カーネル: $(uname -r)"
        echo "アーキテクチャ: $(uname -m)"
        echo "カーネルコマンドライン: $(cat /proc/cmdline)"
        echo
        
        echo "=== CPU情報 ==="
        lscpu
        echo
        echo "CPU使用率 (1分間平均):"
        top -bn1 | grep "Cpu(s)" | head -1
        echo
        
        echo "=== メモリ情報 ==="
        free -h
        echo
        echo "詳細メモリ情報:"
        cat /proc/meminfo | head -20
        echo
        
        echo "=== ストレージ情報 ==="
        echo "ディスク使用量:"
        df -h
        echo
        echo "ブロックデバイス:"
        lsblk -f
        echo
        echo "マウント情報:"
        mount | column -t
        echo
        
        echo "=== ネットワーク情報 ==="
        echo "ネットワークインターフェース:"
        ip addr show
        echo
        echo "ルーティングテーブル:"
        ip route show
        echo
        echo "DNS設定:"
        cat /etc/resolv.conf
        echo
        echo "ネットワーク統計:"
        ss -tuln | head -20
        
    } > "$info_file"
    
    # JSON出力
    if [ "$EXPORT_JSON" = true ]; then
        json_add "os_release" "\"$(cat /etc/redhat-release)\""
        json_add "kernel_version" "\"$(uname -r)\""
        json_add "architecture" "\"$(uname -m)\""
        json_add "hostname" "\"$(hostname)\""
        json_add "uptime" "\"$(uptime)\""
        json_add "cpu_cores" "$(nproc)"
        json_add "memory_total_gb" "$(free -g | grep '^Mem:' | awk '{print $2}')"
        json_add "disk_usage" "\"$(df -h / | tail -1 | awk '{print $5}')\""
    fi
    
    log_info "システム基本情報収集完了: $info_file"
}

# =============================================================================
# AWS EC2特有情報収集
# =============================================================================
collect_aws_info() {
    log_info "AWS EC2情報を収集中..."
    
    local aws_file="$REPORT_DIR/aws_ec2_info.txt"
    
    {
        echo "=== AWS EC2メタデータ情報 ==="
        
        # メタデータサービス可用性確認
        if curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ >/dev/null; then
            echo "Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id)"
            echo "Instance Type: $(curl -s http://169.254.169.254/latest/meta-data/instance-type)"
            echo "AMI ID: $(curl -s http://169.254.169.254/latest/meta-data/ami-id)"
            echo "Availability Zone: $(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)"
            echo "Region: $(curl -s http://169.254.169.254/latest/meta-data/placement/region)"
            echo "Local IPv4: $(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)"
            echo "Public IPv4: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo 'N/A')"
            echo "Security Groups: $(curl -s http://169.254.169.254/latest/meta-data/security-groups)"
            echo "IAM Role: $(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || echo 'N/A')"
            echo
            
            # インスタンスメタデータ詳細
            echo "=== インスタンス詳細情報 ==="
            echo "MAC Address: $(curl -s http://169.254.169.254/latest/meta-data/mac)"
            echo "Launch Time: $(curl -s http://169.254.169.254/latest/meta-data/instance-action)"
            echo "Hostname: $(curl -s http://169.254.169.254/latest/meta-data/hostname)"
            echo
        else
            echo "AWS EC2メタデータサービスにアクセスできません"
            echo "オンプレミス環境または他のクラウドプロバイダーの可能性があります"
        fi
        
        # AWS CLI情報
        echo "=== AWS CLI情報 ==="
        if command -v aws >/dev/null 2>&1; then
            echo "AWS CLI Version: $(aws --version 2>&1)"
            echo "AWS Configuration:"
            aws configure list 2>/dev/null || echo "AWS設定なし"
            echo
            
            # 可能であれば追加情報取得
            if aws sts get-caller-identity >/dev/null 2>&1; then
                echo "Current AWS Identity:"
                aws sts get-caller-identity
                echo
            fi
        else
            echo "AWS CLI がインストールされていません"
        fi
        
        # CloudWatch Agent
        echo "=== CloudWatch Agent ==="
        if systemctl is-active amazon-cloudwatch-agent >/dev/null 2>&1; then
            echo "Status: Active"
            echo "Config: $(ls /opt/aws/amazon-cloudwatch-agent/etc/ 2>/dev/null || echo 'N/A')"
        else
            echo "Status: Inactive or Not Installed"
        fi
        
        # SSM Agent
        echo "=== Systems Manager Agent ==="
        if systemctl is-active amazon-ssm-agent >/dev/null 2>&1; then
            echo "Status: Active"
            systemctl status amazon-ssm-agent --no-pager -l
        else
            echo "Status: Inactive or Not Installed"
        fi
        
    } > "$aws_file"
    
    # JSON出力
    if [ "$EXPORT_JSON" = true ] && curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ >/dev/null; then
        json_add "aws_instance_id" "\"$(curl -s http://169.254.169.254/latest/meta-data/instance-id)\""
        json_add "aws_instance_type" "\"$(curl -s http://169.254.169.254/latest/meta-data/instance-type)\""
        json_add "aws_ami_id" "\"$(curl -s http://169.254.169.254/latest/meta-data/ami-id)\""
        json_add "aws_availability_zone" "\"$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)\""
        json_add "aws_region" "\"$(curl -s http://169.254.169.254/latest/meta-data/placement/region)\""
    fi
    
    log_info "AWS EC2情報収集完了: $aws_file"
}

# =============================================================================
# パッケージとリポジトリ情報収集
# =============================================================================
collect_package_info() {
    log_info "パッケージとリポジトリ情報を収集中..."
    
    local pkg_file="$REPORT_DIR/package_repository_info.txt"
    local pkg_list="$REPORT_DIR/installed_packages.txt"
    
    {
        echo "=== DNFリポジトリ情報 ==="
        dnf repolist --all
        echo
        
        echo "=== 有効なリポジトリ ==="
        dnf repolist --enabled
        echo
        
        echo "=== RHUI確認 ==="
        if dnf repolist | grep -i rhui; then
            echo "RHUI (Red Hat Update Infrastructure) を使用しています"
            echo "これはAWS EC2のPay-As-You-Go (PAYG) インスタンスです"
        else
            echo "RHUIを使用していません"
        fi
        echo
        
        echo "=== サブスクリプション情報 ==="
        subscription-manager status
        echo
        subscription-manager list --installed 2>/dev/null || echo "サブスクリプション情報を取得できません"
        echo
        
        echo "=== EPELリポジトリ確認 ==="
        if dnf repolist | grep -i epel; then
            echo "EPELリポジトリが有効です"
            dnf repolist | grep -i epel
        else
            echo "EPELリポジトリは有効ではありません"
        fi
        echo
        
        echo "=== パッケージ統計 ==="
        echo "インストール済みパッケージ総数: $(rpm -qa | wc -l)"
        echo "RHEL9パッケージ数: $(rpm -qa | grep '\.el9' | wc -l)"
        echo "RHEL8パッケージ数: $(rpm -qa | grep '\.el8' | wc -l)"
        echo "サードパーティパッケージ数: $(rpm -qa | grep -v '\.el[89]' | wc -l)"
        echo
        
    } > "$pkg_file"
    
    # インストール済みパッケージ詳細リスト
    {
        echo "Package Name,Version,Release,Architecture,Install Date,Size"
        rpm -qa --queryformat "%{NAME},%{VERSION},%{RELEASE},%{ARCH},%{INSTALLTIME:date},%{SIZE}\n" | sort
    } > "$pkg_list"
    
    # CSV形式でのパッケージ情報出力
    {
        echo "Package,Version,Architecture,Repository,Summary"
        dnf list installed --quiet 2>/dev/null | tail -n +2 | while read package version repo; do
            if [ ! -z "$package" ]; then
                summary=$(dnf info "$package" 2>/dev/null | grep "Summary" | cut -d: -f2- | xargs || echo "N/A")
                arch=$(echo "$version" | grep -o '\.[^.]*$' | sed 's/\.//')
                ver=$(echo "$version" | sed 's/\.[^.]*$//')
                echo "\"$package\",\"$ver\",\"$arch\",\"$repo\",\"$summary\""
            fi
        done
    } > "$CSV_OUTPUT"
    
    # 重要パッケージの詳細確認
    local important_packages="$REPORT_DIR/important_packages.txt"
    {
        echo "=== 重要パッケージ詳細確認 ==="
        
        # システムパッケージ
        echo "--- システム関連パッケージ ---"
        rpm -qa | grep -E "(kernel|glibc|systemd|dnf|rpm)" | sort
        echo
        
        # 開発ツール
        echo "--- 開発ツール ---"
        rpm -qa | grep -E "(gcc|make|cmake|git|python|java|nodejs)" | sort
        echo
        
        # Webサーバー
        echo "--- Webサーバー ---"
        rpm -qa | grep -E "(httpd|nginx|apache)" | sort
        echo
        
        # データベース
        echo "--- データベース ---"
        rpm -qa | grep -E "(mysql|mariadb|postgresql|sqlite)" | sort
        echo
        
        # セキュリティ
        echo "--- セキュリティ関連 ---"
        rpm -qa | grep -E "(selinux|firewalld|fail2ban|aide)" | sort
        echo
        
        # 監視・ログ
        echo "--- 監視・ログ関連 ---"
        rpm -qa | grep -E "(rsyslog|logrotate|chrony|cron)" | sort
        echo
        
    } > "$important_packages"
    
    log_info "パッケージ情報収集完了: $pkg_file, $pkg_list, $important_packages"
}

# =============================================================================
# サービスとプロセス情報収集
# =============================================================================
collect_service_info() {
    log_info "サービスとプロセス情報を収集中..."
    
    local service_file="$REPORT_DIR/services_processes.txt"
    
    {
        echo "=== systemdサービス状態 ==="
        echo "有効なサービス一覧:"
        systemctl list-unit-files --type=service --state=enabled --no-pager
        echo
        
        echo "実行中のサービス:"
        systemctl list-units --type=service --state=active --no-pager
        echo
        
        echo "失敗したサービス:"
        systemctl list-units --type=service --state=failed --no-pager
        echo
        
        echo "=== 重要サービスの詳細状態 ==="
        important_services=(
            "sshd" "NetworkManager" "firewalld" "chronyd" "rsyslog" "auditd"
            "httpd" "nginx" "postgresql" "mariadb" "mysql"
            "amazon-ssm-agent" "amazon-cloudwatch-agent"
        )
        
        for service in "${important_services[@]}"; do
            if systemctl list-unit-files | grep -q "^$service."; then
                echo "--- $service ---"
                systemctl status "$service" --no-pager -l || echo "$service: サービスが存在しません"
                echo
            fi
        done
        
        echo "=== プロセス情報 ==="
        echo "プロセス数: $(ps aux | wc -l)"
        echo
        echo "CPU使用率上位10プロセス:"
        ps aux --sort=-%cpu | head -11
        echo
        
        echo "メモリ使用率上位10プロセス:"
        ps aux --sort=-%mem | head -11
        echo
        
        echo "=== ポート使用状況 ==="
        ss -tuln | sort -n
        echo
        
        echo "=== cron/タスクスケジューラ ==="
        echo "システムcrontab:"
        crontab -l 2>/dev/null || echo "システムcrontabなし"
        echo
        echo "ユーザーcrontab:"
        for user in $(cut -f1 -d: /etc/passwd); do
            crontab -u "$user" -l 2>/dev/null && echo "User: $user" || true
        done
        echo
        
        echo "systemd timers:"
        systemctl list-timers --no-pager
        
    } > "$service_file"
    
    log_info "サービス情報収集完了: $service_file"
}

# =============================================================================
# セキュリティ設定確認
# =============================================================================
collect_security_info() {
    log_info "セキュリティ設定を確認中..."
    
    local security_file="$REPORT_DIR/security_settings.txt"
    
    {
        echo "=== SELinux設定 ==="
        echo "SELinux Status: $(getenforce)"
        sestatus
        echo
        echo "SELinux拒否ログ (直近10件):"
        ausearch -m AVC -ts recent 2>/dev/null | tail -10 || echo "SELinux拒否ログなし"
        echo
        
        echo "=== ファイアウォール設定 ==="
        if systemctl is-active firewalld >/dev/null 2>&1; then
            echo "Firewalld Status: Active"
            firewall-cmd --list-all
            echo
            echo "開放ポート:"
            firewall-cmd --list-ports
            echo
            echo "許可サービス:"
            firewall-cmd --list-services
        else
            echo "Firewalld Status: Inactive"
            echo "iptables rules:"
            iptables -L -n || echo "iptablesルールを取得できません"
        fi
        echo
        
        echo "=== SSH設定 ==="
        echo "SSHサービス状態:"
        systemctl status sshd --no-pager -l
        echo
        echo "重要なSSH設定:"
        grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups)" /etc/ssh/sshd_config || echo "設定なし"
        echo
        
        echo "=== システム全体暗号化ポリシー ==="
        update-crypto-policies --show
        echo
        
        echo "=== sudo設定 ==="
        echo "sudoers設定:"
        grep -v "^#" /etc/sudoers | grep -v "^$"
        echo
        
        echo "=== 認証設定 ==="
        echo "PAM設定 (password-auth):"
        cat /etc/pam.d/password-auth | grep -v "^#" | grep -v "^$"
        echo
        
        echo "=== ファイルシステム権限確認 ==="
        echo "重要ファイルの権限:"
        ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config
        echo
        echo "SUID/SGID ファイル (重要なもののみ):"
        find /usr/bin /usr/sbin /bin /sbin -perm /6000 -type f 2>/dev/null | head -20
        echo
        
        echo "=== 監査設定 ==="
        if systemctl is-active auditd >/dev/null 2>&1; then
            echo "Audit Status: Active"
            auditctl -s
            echo
            echo "監査ルール:"
            auditctl -l
        else
            echo "Audit Status: Inactive"
        fi
        
    } > "$security_file"
    
    log_info "セキュリティ設定確認完了: $security_file"
}

# =============================================================================
# ログファイル分析
# =============================================================================
collect_log_analysis() {
    log_info "ログファイル分析中..."
    
    local log_analysis="$REPORT_DIR/log_analysis.txt"
    
    {
        echo "=== システムログ分析 ==="
        echo "直近24時間のシステムログエラー:"
        journalctl --since "24 hours ago" --priority=err --no-pager | tail -20
        echo
        
        echo "直近の再起動履歴:"
        last reboot | head -10
        echo
        
        echo "直近のユーザーログイン:"
        last | head -10
        echo
        
        echo "=== エラーログ統計 ==="
        echo "Kernel エラー (直近24時間):"
        journalctl --since "24 hours ago" -k --priority=err --no-pager | wc -l
        echo
        
        echo "systemd エラー (直近24時間):"
        journalctl --since "24 hours ago" -u systemd --priority=err --no-pager | wc -l
        echo
        
        echo "=== ディスク容量警告 ==="
        df -h | awk '$5 > 80 {print "WARNING: " $0}'
        echo
        
        echo "=== メモリ使用量履歴 ==="
        echo "現在のメモリ使用状況:"
        free -h
        echo
        echo "スワップ使用状況:"
        swapon --show
        
    } > "$log_analysis"
    
    log_info "ログ分析完了: $log_analysis"
}

# =============================================================================
# パフォーマンステスト
# =============================================================================
run_performance_tests() {
    log_info "パフォーマンステストを実行中..."
    
    local perf_file="$REPORT_DIR/performance_test.txt"
    
    {
        echo "=== パフォーマンステスト結果 ==="
        echo "テスト実行時刻: $(date)"
        echo
        
        echo "=== CPU性能テスト ==="
        echo "CPU情報:"
        lscpu | grep -E "(Model name|CPU\(s\)|Thread|MHz)"
        echo
        echo "CPU負荷テスト (5秒間):"
        time (dd if=/dev/zero of=/dev/null bs=1M count=1000 2>/dev/null)
        echo
        
        echo "=== メモリ性能テスト ==="
        echo "メモリ書き込みテスト (100MB):"
        time (dd if=/dev/zero of=/tmp/memtest bs=1M count=100 2>/dev/null; sync)
        rm -f /tmp/memtest
        echo
        
        echo "=== ディスクI/O性能テスト ==="
        echo "ディスク書き込みテスト (100MB, Direct I/O):"
        time (dd if=/dev/zero of=/tmp/disktest bs=1M count=100 oflag=direct 2>/dev/null; sync)
        echo
        echo "ディスク読み取りテスト (100MB, Direct I/O):"
        time (dd if=/tmp/disktest of=/dev/null bs=1M iflag=direct 2>/dev/null)
        rm -f /tmp/disktest
        echo
        
        echo "=== ネットワーク性能テスト ==="
        echo "DNS解決テスト:"
        time (nslookup google.com >/dev/null 2>&1)
        echo
        echo "外部接続テスト:"
        time (curl -s http://httpbin.org/get >/dev/null)
        echo
        
        echo "=== システム負荷情報 ==="
        echo "Load Average:"
        uptime
        echo
        echo "プロセス統計:"
        cat /proc/loadavg
        echo
        echo "I/O統計:"
        iostat 1 1 2>/dev/null || echo "iostat not available"
        
    } > "$perf_file"
    
    log_info "パフォーマンステスト完了: $perf_file"
}

# =============================================================================
# RHEL10互換性チェック
# =============================================================================
check_rhel10_compatibility() {
    log_info "RHEL10互換性をチェック中..."
    
    local compat_file="$REPORT_DIR/rhel10_compatibility.txt"
    
    {
        echo "=== RHEL10互換性チェック ==="
        echo "チェック実行時刻: $(date)"
        echo
        
        echo "=== ハードウェア互換性 ==="
        echo "CPUアーキテクチャ: $(uname -m)"
        
        # x86-64-v3 サポートチェック
        if [ "$(uname -m)" = "x86_64" ]; then
            echo "x86-64-v3 サポートチェック:"
            if [ -f /proc/cpuinfo ]; then
                # 簡易的なチェック（実際のx86-64-v3判定は複雑）
                if grep -q "avx2" /proc/cpuinfo && grep -q "fma" /proc/cpuinfo; then
                    echo "✅ CPUは新しい命令セットをサポートしている可能性があります"
                else
                    echo "⚠️  CPUが古い可能性があります。詳細な確認が必要です"
                fi
            fi
        fi
        echo
        
        echo "=== ソフトウェア互換性 ==="
        
        # Python互換性
        echo "--- Python互換性 ---"
        if command -v python3 >/dev/null; then
            python3 --version
            echo "Python 3.12サポート: $(python3.12 --version 2>/dev/null || echo 'Not installed')"
        fi
        echo
        
        # Java互換性
        echo "--- Java互換性 ---"
        if command -v java >/dev/null; then
            java -version 2>&1 | head -3
            echo "Java 17サポート: $(java -version 2>&1 | grep -o 'version.*17' || echo 'Not Java 17')"
        fi
        echo
        
        # 非互換パッケージチェック
        echo "--- 潜在的な非互換パッケージ ---"
        problematic_packages=(
            "python2" "java-1.8.0" "nodejs-8" "nodejs-10" "nodejs-12"
            "mysql57" "postgresql-9"
        )
        
        for pkg in "${problematic_packages[@]}"; do
            if rpm -q "$pkg" >/dev/null 2>&1; then
                echo "⚠️  $pkg: RHEL10で問題となる可能性があります"
            fi
        done
        echo
        
        echo "=== 設定ファイル互換性 ==="
        echo "--- Apache設定 ---"
        if [ -f /etc/httpd/conf/httpd.conf ]; then
            echo "Apache設定ファイル存在: ✅"
            # 非互換設定のチェック
            if grep -q "LoadModule.*mod_auth_digest" /etc/httpd/conf/httpd.conf 2>/dev/null; then
                echo "⚠️  mod_auth_digestの使用を検出: RHEL10で変更が必要な可能性"
            fi
        fi
        echo
        
        echo "--- Systemdサービス ---"
        echo "カスタムサービス数: $(ls /etc/systemd/system/*.service 2>/dev/null | wc -l)"
        if [ -d /etc/systemd/system ]; then
            echo "カスタムサービス一覧:"
            ls /etc/systemd/system/*.service 2>/dev/null | head -10 || echo "カスタムサービスなし"
        fi
        echo
        
        echo "=== ネットワーク設定互換性 ==="
        echo "--- NetworkManager設定 ---"
        if systemctl is-active NetworkManager >/dev/null 2>&1; then
            echo "NetworkManager: ✅ Active"
            echo "接続プロファイル:"
            nmcli connection show 2>/dev/null | head -5 || echo "NetworkManager情報取得不可"
        else
            echo "NetworkManager: ❌ Not Active"
            echo "⚠️  RHEL10ではNetworkManagerが推奨されます"
        fi
        echo
        
        echo "=== データベース互換性チェック ==="
        
        # PostgreSQL
        if systemctl is-active postgresql >/dev/null 2>&1; then
            echo "--- PostgreSQL ---"
            psql_version=$(sudo -u postgres psql -c "SELECT version();" 2>/dev/null | grep PostgreSQL || echo "Version check failed")
            echo "現在のバージョン: $psql_version"
            echo "RHEL10推奨: PostgreSQL 16"
        fi
        
        # MySQL/MariaDB
        if systemctl is-active mariadb >/dev/null 2>&1 || systemctl is-active mysql >/dev/null 2>&1; then
            echo "--- MySQL/MariaDB ---"
            mysql_version=$(mysql --version 2>/dev/null || echo "Version check failed")
            echo "現在のバージョン: $mysql_version"
            echo "RHEL10推奨: MariaDB 10.11"
        fi
        echo
        
        echo "=== 重要な変更点チェック ==="
        echo "--- OpenSSL Engine API ---"
        if rpm -qa | grep -q openssl-pkcs11; then
            echo "⚠️  OpenSSL PKCS#11 Engine検出: RHEL10ではpkcs11-providerに移行が必要"
        fi
        
        echo "--- Redis → Valkey移行 ---"
        if rpm -qa | grep -q redis; then
            echo "⚠️  Redisパッケージ検出: RHEL10ではValkeyに置き換えられます"
        fi
        
        echo "--- Java 8削除 ---"
        if rpm -qa | grep -q java-1.8.0; then
            echo "❌ Java 8検出: RHEL10では削除されます。Java 11以上への移行が必要"
        fi
        
        echo "--- X.org Server削除 ---"
        if rpm -qa | grep -q xorg-x11-server; then
            echo "⚠️  X.org Server検出: RHEL10ではWaylandベースへの移行が推奨"
        fi
        
    } > "$compat_file"
    
    log_info "RHEL10互換性チェック完了: $compat_file"
}

# =============================================================================
# カスタム設定確認
# =============================================================================
check_custom_configurations() {
    log_info "カスタム設定を確認中..."
    
    local custom_file="$REPORT_DIR/custom_configurations.txt"
    
    {
        echo "=== カスタム設定確認 ==="
        echo "確認実行時刻: $(date)"
        echo
        
        echo "=== 環境変数設定 ==="
        echo "--- システム環境変数 ---"
        env | grep -E "(PATH|LD_LIBRARY_PATH|JAVA_HOME|PYTHON_PATH)" | sort
        echo
        
        echo "--- /etc/environment ---"
        if [ -f /etc/environment ]; then
            cat /etc/environment
        else
            echo "/etc/environment ファイルは存在しません"
        fi
        echo
        
        echo "=== カスタムリポジトリ確認 ==="
        echo "--- /etc/yum.repos.d/ 内のカスタムリポジトリ ---"
        for repo_file in /etc/yum.repos.d/*.repo; do
            if [ -f "$repo_file" ] && ! [[ "$repo_file" =~ (redhat|rhui|epel) ]]; then
                echo "カスタムリポジトリファイル: $repo_file"
                grep -E "^\[.*\]|^name=|^enabled=" "$repo_file" 2>/dev/null | head -10
                echo
            fi
        done
        
        echo "=== アプリケーション設定 ==="
        
        # Apache設定
        if [ -d /etc/httpd ]; then
            echo "--- Apache設定 ---"
            echo "設定ファイル一覧:"
            find /etc/httpd -name "*.conf" | head -10
            echo
            echo "バーチャルホスト設定:"
            grep -r "VirtualHost" /etc/httpd/ 2>/dev/null | head -5 || echo "バーチャルホスト設定なし"
            echo
            echo "カスタムモジュール:"
            grep -r "LoadModule" /etc/httpd/conf.d/ 2>/dev/null | head -5 || echo "カスタムモジュール設定なし"
            echo
        fi
        
        # Nginx設定
        if [ -d /etc/nginx ]; then
            echo "--- Nginx設定 ---"
            echo "設定ファイル一覧:"
            find /etc/nginx -name "*.conf" | head -10
            echo
            echo "サーバーブロック設定:"
            grep -r "server_name" /etc/nginx/ 2>/dev/null | head -5 || echo "サーバーブロック設定なし"
            echo
        fi
        
        # PHP設定
        if [ -d /etc/php.ini ] || [ -d /etc/php ]; then
            echo "--- PHP設定 ---"
            if [ -f /etc/php.ini ]; then
                echo "PHP設定ファイル: /etc/php.ini"
                grep -E "^(memory_limit|max_execution_time|upload_max_filesize)" /etc/php.ini 2>/dev/null || echo "主要設定なし"
            fi
            echo
        fi
        
        echo "=== データベース設定 ==="
        
        # PostgreSQL設定
        if [ -d /var/lib/pgsql ]; then
            echo "--- PostgreSQL設定 ---"
            pg_config_dir=$(find /var/lib/pgsql -name "postgresql.conf" -type f 2>/dev/null | head -1)
            if [ -n "$pg_config_dir" ]; then
                echo "設定ファイル: $pg_config_dir"
                grep -E "^(listen_addresses|port|max_connections)" "$(dirname "$pg_config_dir")/postgresql.conf" 2>/dev/null || echo "設定確認不可"
            fi
            echo
        fi
        
        # MySQL/MariaDB設定
        if [ -f /etc/my.cnf ] || [ -d /etc/my.cnf.d ]; then
            echo "--- MySQL/MariaDB設定 ---"
            if [ -f /etc/my.cnf ]; then
                echo "メイン設定ファイル: /etc/my.cnf"
                grep -E "^\[|^bind-address|^port" /etc/my.cnf 2>/dev/null | head -10
            fi
            if [ -d /etc/my.cnf.d ]; then
                echo "追加設定ファイル:"
                ls /etc/my.cnf.d/*.cnf 2>/dev/null
            fi
            echo
        fi
        
        echo "=== 自動化・監視設定 ==="
        
        # Crontab詳細
        echo "--- Crontab詳細 ---"
        echo "システムcrontab:"
        cat /etc/crontab 2>/dev/null || echo "システムcrontabなし"
        echo
        echo "cron.d設定:"
        ls /etc/cron.d/ 2>/dev/null | head -10 || echo "cron.d設定なし"
        echo
        
        # Logrotate設定
        echo "--- Logrotate設定 ---"
        echo "カスタムログローテーション設定:"
        ls /etc/logrotate.d/ 2>/dev/null | grep -v -E "(bootlog|btmp|chrony|dnf|ppp|rpm|sssd|subscription-manager|wtmp|yum)" | head -10
        echo
        
        echo "=== SSL/TLS証明書 ==="
        echo "--- 証明書ファイル ---"
        find /etc/ssl /etc/pki -name "*.crt" -o -name "*.pem" 2>/dev/null | head -10
        echo
        echo "--- 証明書有効期限チェック ---"
        for cert in /etc/ssl/certs/*.crt /etc/pki/tls/certs/*.crt; do
            if [ -f "$cert" ]; then
                expiry=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
                if [ -n "$expiry" ]; then
                    echo "$cert: $expiry"
                fi
            fi
        done | head -5
        
    } > "$custom_file"
    
    log_info "カスタム設定確認完了: $custom_file"
}

# =============================================================================
# 移行リスク評価
# =============================================================================
assess_migration_risks() {
    log_info "移行リスク評価中..."
    
    local risk_file="$REPORT_DIR/migration_risk_assessment.txt"
    local risk_score=0
    
    {
        echo "=== RHEL9→RHEL10移行リスク評価 ==="
        echo "評価実行時刻: $(date)"
        echo
        
        echo "=== 高リスク要因 ==="
        
        # Java 8使用チェック
        if rpm -qa | grep -q java-1.8.0; then
            echo "❌ HIGH: Java 8が使用されています（RHEL10で削除）"
            ((risk_score += 20))
        fi
        
        # Python 2使用チェック
        if rpm -qa | grep -q python2; then
            echo "❌ HIGH: Python 2が使用されています（サポート終了）"
            ((risk_score += 15))
        fi
        
        # 古いデータベースバージョン
        if rpm -qa | grep -E "(mysql-5|postgresql-9|postgresql-10)"; then
            echo "❌ HIGH: 古いデータベースバージョンが使用されています"
            ((risk_score += 15))
        fi
        
        # カスタムコンパイルソフトウェア
        custom_software=$(find /opt /usr/local -type f -executable 2>/dev/null | wc -l)
        if [ "$custom_software" -gt 10 ]; then
            echo "⚠️  HIGH: カスタムソフトウェアが多数存在します ($custom_software 個)"
            ((risk_score += 10))
        fi
        
        echo
        echo "=== 中リスク要因 ==="
        
        # サードパーティリポジトリ
        third_party_repos=$(find /etc/yum.repos.d -name "*.repo" | grep -v -E "(redhat|rhui|epel)" | wc -l)
        if [ "$third_party_repos" -gt 0 ]; then
            echo "⚠️  MEDIUM: サードパーティリポジトリが $third_party_repos 個存在します"
            ((risk_score += 8))
        fi
        
        # 大量データ
        large_databases=$(find /var/lib/pgsql /var/lib/mysql -size +1G 2>/dev/null | wc -l)
        if [ "$large_databases" -gt 0 ]; then
            echo "⚠️  MEDIUM: 大容量データベースファイルが存在します"
            ((risk_score += 5))
        fi
        
        # 多数のカスタム設定
        custom_configs=$(find /etc -name "*.conf" -newer /etc/passwd 2>/dev/null | wc -l)
        if [ "$custom_configs" -gt 20 ]; then
            echo "⚠️  MEDIUM: カスタム設定ファイルが多数存在します ($custom_configs 個)"
            ((risk_score += 5))
        fi
        
        echo
        echo "=== 低リスク要因 ==="
        
        # SELinux Permissive/Disabled
        if [ "$(getenforce)" != "Enforcing" ]; then
            echo "ℹ️  LOW: SELinuxがEnforcingモードではありません"
            ((risk_score += 3))
        fi
        
        # 古いカーネル
        kernel_version=$(uname -r | cut -d. -f1-2)
        if [[ "$kernel_version" < "5.14" ]]; then
            echo "ℹ️  LOW: 古いカーネルバージョンです"
            ((risk_score += 2))
        fi
        
        echo
        echo "=== リスクスコア算出 ==="
        echo "総合リスクスコア: $risk_score / 100"
        
        if [ "$risk_score" -ge 50 ]; then
            echo "🔴 高リスク: 慎重な計画と十分なテストが必要です"
        elif [ "$risk_score" -ge 25 ]; then
            echo "🟡 中リスク: 注意深い移行計画が推奨されます"
        else
            echo "🟢 低リスク: 標準的な移行手順で対応可能と思われます"
        fi
        
        echo
        echo "=== 推奨対応策 ==="
        
        if rpm -qa | grep -q java-1.8.0; then
            echo "• Java 8 → Java 17への移行準備"
            echo "  - アプリケーションの互換性テスト"
            echo "  - JVMパラメータの調整"
        fi
        
        if rpm -qa | grep -q python2; then
            echo "• Python 2 → Python 3への移行"
            echo "  - スクリプトの書き換え"
            echo "  - ライブラリの更新"
        fi
        
        if [ "$third_party_repos" -gt 0 ]; then
            echo "• サードパーティリポジトリの互換性確認"
            echo "  - RHEL10対応版の確認"
            echo "  - 代替パッケージの検討"
        fi
        
        echo "• Blue-Green移行戦略の採用推奨（AWS EC2 RHUI環境）"
        echo "• 段階的移行（開発→ステージング→本番）"
        echo "• 完全バックアップとロールバック計画"
        
        echo
        echo "=== 移行スケジュール推奨 ==="
        if [ "$risk_score" -ge 50 ]; then
            echo "推奨期間: 6-8週間"
            echo "• 準備・調査: 2週間"
            echo "• 開発環境検証: 2週間"  
            echo "• ステージング移行: 2週間"
            echo "• 本番移行: 2週間"
        elif [ "$risk_score" -ge 25 ]; then
            echo "推奨期間: 4-6週間"
            echo "• 準備・調査: 1週間"
            echo "• 開発環境検証: 1-2週間"
            echo "• ステージング移行: 1週間" 
            echo "• 本番移行: 1-2週間"
        else
            echo "推奨期間: 3-4週間"
            echo "• 準備・調査: 1週間"
            echo "• 開発環境検証: 1週間"
            echo "• ステージング移行: 1週間"
            echo "• 本番移行: 1週間"
        fi
        
    } > "$risk_file"
    
    # JSON出力
    if [ "$EXPORT_JSON" = true ]; then
        json_add "migration_risk_score" "$risk_score"
        json_add "migration_risk_level" "\"$([ "$risk_score" -ge 50 ] && echo "HIGH" || [ "$risk_score" -ge 25 ] && echo "MEDIUM" || echo "LOW")\""
    fi
    
    log_info "移行リスク評価完了: $risk_file (リスクスコア: $risk_score)"
}

# =============================================================================
# HTMLレポート生成
# =============================================================================
generate_html_report() {
    if [ "$GENERATE_HTML" = false ]; then
        return
    fi
    
    log_info "HTMLレポートを生成中..."
    
    cat > "$HTML_REPORT" << 'EOF'
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RHEL10移行システム詳細レポート</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #cc0000, #ff4444);
            color: white;
            padding: 20px;
            margin: -30px -30px 30px -30px;
            border-radius: 8px 8px 0 0;
            text-align: center;
        }
        .section {
            margin: 30px 0;
            padding: 20px;
            border-left: 4px solid #cc0000;
            background: #f9f9f9;
        }
        .section h2 {
            margin-top: 0;
            color: #cc0000;
        }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .status-error { color: #dc3545; font-weight: bold; }
        .metric {
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 15px;
            background: white;
            border-radius: 5px;
            border: 1px solid #ddd;
            min-width: 150px;
            text-align: center;
        }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        .metric-label {
            font-size: 14px;
            color: #666;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .risk-high { background-color: #f8d7da; color: #721c24; }
        .risk-medium { background-color: #fff3cd; color: #856404; }
        .risk-low { background-color: #d4edda; color: #155724; }
        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 12px;
        }
        .nav-menu {
            background: #333;
            padding: 10px 0;
            margin: -30px -30px 30px -30px;
            text-align: center;
        }
        .nav-menu a {
            color: white;
            text-decoration: none;
            margin: 0 15px;
            padding: 5px 10px;
            border-radius: 3px;
            transition: background 0.3s;
        }
        .nav-menu a:hover {
            background: #555;
        }
        .collapsible {
            cursor: pointer;
            padding: 10px;
            background: #e9ecef;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
            width: 100%;
            border-radius: 5px;
            margin: 5px 0;
        }
        .collapsible:hover {
            background: #dee2e6;
        }
        .content {
            padding: 0 15px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background: white;
        }
        .active + .content {
            max-height: 500px;
            padding: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 RHEL10移行システム詳細レポート</h1>
            <p>生成日時: $(date) | ホスト: $(hostname)</p>
        </div>
        
        <div class="nav-menu">
            <a href="#overview">概要</a>
            <a href="#system">システム情報</a>
            <a href="#aws">AWS情報</a>
            <a href="#packages">パッケージ</a>
            <a href="#services">サービス</a>
            <a href="#security">セキュリティ</a>
            <a href="#compatibility">互換性</a>
            <a href="#risks">リスク評価</a>
        </div>

        <div id="overview" class="section">
            <h2>📊 システム概要</h2>
            <div class="metric">
                <div class="metric-value">$(cat /etc/redhat-release | cut -d' ' -f1-4)</div>
                <div class="metric-label">現在のOS</div>
            </div>
            <div class="metric">
                <div class="metric-value">$(uname -r | cut -d'.' -f1-3)</div>
                <div class="metric-label">カーネル</div>
            </div>
            <div class="metric">
                <div class="metric-value">$(uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')</div>
                <div class="metric-label">稼働時間</div>
            </div>
            <div class="metric">
                <div class="metric-value">$(rpm -qa | wc -l)</div>
                <div class="metric-label">パッケージ数</div>
            </div>
        </div>

EOF

    # システム情報セクション
    if [ -f "$REPORT_DIR/system_basic_info.txt" ]; then
        cat >> "$HTML_REPORT" << EOF
        <div id="system" class="section">
            <h2>🖥️ システム情報</h2>
            <button class="collapsible">システム基本情報</button>
            <div class="content">
                <pre>$(head -50 "$REPORT_DIR/system_basic_info.txt")</pre>
            </div>
        </div>
EOF
    fi

    # AWS情報セクション
    if [ -f "$REPORT_DIR/aws_ec2_info.txt" ]; then
        cat >> "$HTML_REPORT" << EOF
        <div id="aws" class="section">
            <h2>☁️ AWS EC2情報</h2>
            <button class="collapsible">AWS EC2詳細情報</button>
            <div class="content">
                <pre>$(cat "$REPORT_DIR/aws_ec2_info.txt")</pre>
            </div>
        </div>
EOF
    fi

    # 互換性チェック結果
    if [ -f "$REPORT_DIR/rhel10_compatibility.txt" ]; then
        cat >> "$HTML_REPORT" << EOF
        <div id="compatibility" class="section">
            <h2>🔍 RHEL10互換性チェック</h2>
            <button class="collapsible">互換性詳細</button>
            <div class="content">
                <pre>$(cat "$REPORT_DIR/rhel10_compatibility.txt")</pre>
            </div>
        </div>
EOF
    fi

    # リスク評価結果
    if [ -f "$REPORT_DIR/migration_risk_assessment.txt" ]; then
        cat >> "$HTML_REPORT" << EOF
        <div id="risks" class="section">
            <h2>⚠️ 移行リスク評価</h2>
            <button class="collapsible">リスク評価詳細</button>
            <div class="content">
                <pre>$(cat "$REPORT_DIR/migration_risk_assessment.txt")</pre>
            </div>
        </div>
EOF
    fi

    # JavaScript追加
    cat >> "$HTML_REPORT" << 'EOF'
        <div class="section">
            <h2>📄 詳細レポートファイル</h2>
            <p>以下のファイルに詳細情報が保存されています：</p>
            <ul>
EOF

    # ファイルリスト追加
    for file in "$REPORT_DIR"/*.txt "$REPORT_DIR"/*.csv; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            echo "                <li>$filename</li>" >> "$HTML_REPORT"
        fi
    done

    cat >> "$HTML_REPORT" << 'EOF'
            </ul>
        </div>
    </div>

    <script>
        // Collapsible sections
        var coll = document.getElementsByClassName("collapsible");
        for (var i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                } else {
                    content.style.maxHeight = content.scrollHeight + "px";
                }
            });
        }

        // Smooth scrolling for navigation
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });
    </script>
</body>
</html>
EOF

    log_info "HTMLレポート生成完了: $HTML_REPORT"
}

# =============================================================================
# JSON出力完了
# =============================================================================
finalize_json_output() {
    if [ "$EXPORT_JSON" = true ]; then
        # JSON終了
        sed -i '$ s/,$//' "$JSON_OUTPUT"  # 最後のカンマを削除
        echo '}' >> "$JSON_OUTPUT"
        log_info "JSON出力完了: $JSON_OUTPUT"
    fi
}

# =============================================================================
# レポートサマリー生成
# =============================================================================
generate_summary() {
    log_info "サマリーレポートを生成中..."
    
    local summary_file="$REPORT_DIR/executive_summary.txt"
    
    {
        echo "========================================================"
        echo "    RHEL10移行システム検証 エグゼクティブサマリー"
        echo "========================================================"
        echo "生成日時: $(date)"
        echo "対象システム: $(hostname)"
        echo "現在のOS: $(cat /etc/redhat-release)"
        echo
        
        echo "=== 重要な発見事項 ==="
        
        # AWS環境確認
        if curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ >/dev/null; then
            instance_type=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
            echo "• AWS EC2環境: $instance_type"
            if dnf repolist | grep -qi rhui; then
                echo "• RHUI使用: ✅ （PAYGインスタンス）"
                echo "• 推奨移行方式: Blue-Green戦略"
            fi
        fi
        
        # 互換性問題
        if rpm -qa | grep -q java-1.8.0; then
            echo "• ❌ Java 8検出: RHEL10で削除されるため移行必須"
        fi
        
        if rpm -qa | grep -q python2; then
            echo "• ❌ Python 2検出: サポート終了のため移行必須"
        fi
        
        if rpm -qa | grep -q redis; then
            echo "• ⚠️  Redis検出: RHEL10ではValkeyに置き換え"
        fi
        
        # システムリソース
        memory_usage=$(free | grep '^Mem:' | awk '{printf "%.1f%%", $3/$2*100}')
        disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
        echo "• システムリソース: メモリ $memory_usage, ディスク ${disk_usage}%"
        
        # パッケージ統計
        total_packages=$(rpm -qa | wc -l)
        rhel9_packages=$(rpm -qa | grep '\.el9' | wc -l)
        custom_packages=$(rpm -qa | grep -v '\.el[89]' | wc -l)
        echo "• パッケージ: 総数 $total_packages (RHEL9: $rhel9_packages, カスタム: $custom_packages)"
        
        echo
        echo "=== 推奨アクション ==="
        echo "1. Blue-Green移行戦略の採用（AWS RHUI環境のため）"
        echo "2. 互換性問題のあるパッケージの事前移行"
        echo "3. 段階的移行の実施（開発→ステージング→本番）"
        echo "4. 完全バックアップとロールバック計画の作成"
        
        if [ -f "$REPORT_DIR/migration_risk_assessment.txt" ]; then
            risk_level=$(grep "総合リスクスコア" "$REPORT_DIR/migration_risk_assessment.txt" | cut -d: -f2)
            echo "5. リスクレベル:$risk_level"
        fi
        
        echo
        echo "=== 次のステップ ==="
        echo "1. 詳細レポートの確認: $REPORT_DIR/"
        echo "2. 開発環境での移行テスト実施"
        echo "3. アプリケーション固有の互換性テスト"
        echo "4. 移行スケジュールの策定"
        
        echo
        echo "=== 生成されたファイル ==="
        ls -la "$REPORT_DIR"/ | grep -v "^total"
        
    } > "$summary_file"
    
    log_info "サマリーレポート生成完了: $summary_file"
    
    # サマリーをコンソールにも出力
    echo
    echo "========================================================"
    echo "           詳細システム検証完了"
    echo "========================================================"
    cat "$summary_file"
}

# =============================================================================
# メイン実行関数
# =============================================================================
main() {
    log_info "RHEL10移行詳細確認スクリプト開始"
    
    # root権限チェック
    if [[ $EUID -ne 0 ]]; then
        log_error "このスクリプトはroot権限で実行する必要があります"
        echo "使用方法: sudo $0 [--report-html] [--export-json]"
        exit 1
    fi
    
    log_info "レポート出力ディレクトリ: $REPORT_DIR"
    
    # 情報収集実行
    collect_system_info
    collect_aws_info
    collect_package_info
    collect_service_info
    collect_security_info
    collect_log_analysis
    check_rhel10_compatibility
    check_custom_configurations
    assess_migration_risks
    run_performance_tests
    
    # レポート生成
    generate_html_report
    finalize_json_output
    generate_summary
    
    log_info "詳細確認スクリプト完了"
}

# スクリプト実行
main "$@"
            
