#!/bin/bash

# 设置日志文件
LOG_FILE="system_security_audit_$(date +%Y%m%d).log"
exec > >(tee "$LOG_FILE") 2>&1

# 颜色编码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'



WEB_DIRS=(
  "/var/www/html"
  "/var/www"
  "/usr/share/nginx/html"
  "/www"
  "/home/*/public_html"
  "/home/*/www"
  "/opt/lampp/htdocs"
  "/var/lib/mysql-files"
  # 根据实际情况添加更多目录
)

# 白名单目录配置
WHITELIST_DIRS=(
  "/vendor/*"
  "/phpmyadmin/*"
  # 根据实际情况添加更多白名单路径
)

# PHP WebShell查杀规则
PHP_WEBSHELL_RULES=(
  'array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|gunerpress|base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\('
  '^\xff\xd8[\s\S]*<\?\s*php'
  '\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))'
  '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))'
  '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))'
  "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input"
  'getruntime|processimpl|processbuilder|defineclass|classloader|naming.lookup|internaldofilter|elprocessor|scriptenginemanager|urlclassloader|versionhelper|registermapping|registerhandler|detecthandlermethods|\\u0063\\u006c\\u0061\\u0073\\u0073'
  'phpinfo|move_uploaded_file|system|shell_exec|passthru|popen|proc_open|pcntl_exec|call_user_func|ob_start'
  'array_map|uasort|uksort|array_diff_uassoc|array_diff_ukey|array_intersect_uassoc|array_intersect_ukey|array_reduce|array_filter|array_udiff|array_udiff_assoc|array_udiff_uassoc|array_uintersect|array_uintersect_assoc|array_uintersect_uassoc|array_walk|array_walk_recursive|register_shutdown_function|register_tick_function|filter_var_array|yaml_parse|sqlite_create_function|fgetc|fgets|fgetss|fpassthru|fread|file_get_contents|readfile|stream_get_contents|stream_get_line|highlight_file|show_source|file_put_contents|pfsockopen|fsockopen'
)


# 修改echo输出格式
echo_check() {
  local service="$1"
  local message="$2"
  local type="$3"  # info, warning, error
  
  case "$type" in
    "info")
      echo -e "${GREEN}[$service] $message${NC}"
      ;;
    "warning")
      echo -e "${YELLOW}[$service] $message${NC}"
      ;;
    "error")
      echo -e "${RED}[$service] $message${NC}"
      ;;
    *)
      echo -e "[$service] $message"
      ;;
  esac
}



# 检查脚本是否以root权限运行
if [ "$EUID" -ne 0 ]; then
  echo_check "权限检查" "请以root权限运行此脚本！" "error"
  exit 1
fi

# 判断系统类型
if grep -qEi "ubuntu|debian" /etc/issue || [ -f /etc/debian_version ]; then
  SYSTEM_TYPE="debian"
elif grep -qEi "centos|rhel" /etc/issue || [ -f /etc/redhat-release ]; then
  SYSTEM_TYPE="redhat"
else
  echo_check "系统类型" "未知操作系统类型，部分功能可能无法正常运行。" "warning"
fi

# 标题

echo_check " ####      ######  ##   ##   ##  ##  ##    ##           #####   #######    ####    ##  ##  #######    ####   ###  ## " "error"
echo_check "  ##         ##    ###  ##   ##  ##   ##  ##           ##   ##   ##  ##   ##  ##   ##  ##   ##  ##   ##  ##   ##  ## " "error"
echo_check "  ##         ##    #### ##   ##  ##    ####            ###       ##      ##        ##  ##   ##      ##        ## ##  " "error"
echo_check "  ##         ##    ## ####   ##  ##     ##               ###     ####    ##        ######   ####    ##        ####   " "error"
echo_check "  ##   #     ##    ##  ###   ##  ##    ####                ###   ##      ##        ##  ##   ##      ##        ## ##  " "error"
echo_check "  ##  ##     ##    ##   ##   ##  ##   ##  ##           ##   ##   ##  ##   ##  ##   ##  ##   ##  ##   ##  ##   ##  ## " "error" 
echo_check " #######   ######  ##   ##    #####  ##    ##           #####   #######    ####    ##  ##  #######    ####   ###  ## " "error"



echo_check "系统安全" "Linux系统深度安全自查开始" "info"
echo "================================"
# 版权声明
echo_check "版权声明" "本脚本由Lyscf开发，仅供学习和交流使用。" "warning"
echo_check "版权声明" "项目基于AGPL3.0开源协议开源，请在二次开发时保留此部分版权信息" "warning"
echo_check "版权声明" "项目地址：https://github.com/lyscf/AWD-SecCheck" "warning"
echo_check "版权声明" "如果您在使用过程中出现问题或需要提出反馈，欢迎通过Github联系我" "warning"
echo_check "版权声明" "感谢您的支持！" "warning"
echo "================================"
echo_check "免责声明" "本脚本仅供学习和交流使用，使用者需遵守当地法律法规，禁止用于非法用途" "warning"
echo_check "免责声明" "使用者对使用本脚本所造成的后果自行承担，与本人无关" "warning"
echo_check "免责声明" "由于规则的局限性和绕过方式的多样性，本自查脚本的判断结果仅供参考，请勿过分相信" "warning"
echo_check "免责声明" "如有疑问或发现问题，请及时联系作者，感谢您的支持！" "warning"
echo "================================"






# 系统清理
clean_cache_files() {
  echo_check "系统清理" "清理不必要的缓存文件..." "info"
  rm -rf /root/.cache/pip/*
  find /tmp /var/tmp -type f -atime +1 -delete
  echo_check "系统清理" "已清理缓存文件。" "info"
}

# 系统基本信息收集
collect_system_info() {
  echo_check "系统信息" "收集系统信息..." "info"
  uname -a
  lsb_release -a 2>/dev/null

  echo_check "系统信息" "收集已安装的软件..." "info"
  installed_software=("nginx" "apache2" "httpd" "firewalld" "php" "ufw" "iptables" "redis" "mysql" "mariadb" "mongodb" "postgresql" "caddy" "openresty" "fail2ban")
  for software in "${installed_software[@]}"; do
    if command -v "$software" >/dev/null 2>&1; then
      echo_check "$software" "已安装" "info"
    else
      echo_check "$software" "未安装" "error"
    fi
  done
}

# 动态查找配置文件
find_config_files() {
  echo_check "配置文件查找" "动态查找配置文件..." "info"

  SERVICES=("nginx" "apache2" "httpd" "firewalld" "php" "ufw" "iptables" "redis" "mysql" "mariadb" "mongodb" "postgresql" "caddy" "openresty" "fail2ban")

  for service in "${SERVICES[@]}"; do
    echo_check "配置文件查找" "正在查找 $service 的配置文件..." "info"
    config_found=false
    for path in "/etc/$service/$service.conf" "/etc/$service.conf" "/etc/$service.d/" "/usr/local/etc/$service/"; do
      if [ -f "$path" ] || [ -d "$path" ]; then
        config_file="$path"
        config_found=true
        break
      fi
    done

    if ! $config_found; then
      config_file=$(find /etc /usr/local -type f -name "*$service*.conf" 2>/dev/null | head -n 1)
    fi

    if [ -n "$config_file" ]; then
      file_name=$(basename "$config_file")
      config_dir="/var/tmp/security_audit"
      mkdir -p "$config_dir"
      cp "$config_file" "$config_dir/$file_name" 2>/dev/null
      if [ $? -eq 0 ]; then
        echo_check "配置文件查找" "已复制: $file_name" "info"
      else
        echo_check "配置文件查找" "复制失败: $file_name" "error"
      fi
    else
      echo_check "配置文件查找" "未找到 $service 的配置文件" "error"
    fi
  done
}

# 服务状态和安全检查
check_suspicious_processes() {
  echo_check "进程检查" "开始检查可疑进程及路径..." "info"
  ps aux | grep -v grep | grep -E "(nc|netcat|bash.*-c|sh -c|wget|curl|telnet|perl.*-e|python.*-c|java.*-jar|ruby.*-e|python -c|perl -e|base64_decode|eval|system|passthru)" && echo_check "进程检查" "发现可疑进程" "error"
}

check_systemd_service_status() {
  echo_check "systemd服务" "检查systemd服务状态..." "info"
  systemctl list-units --type=service --state=running | grep -vE "systemd|dbus|NetworkManager|rsyslog"
}

check_abnormal_service_file_permissions() {
  echo_check "服务文件权限" "检查异常服务文件权限..." "info"
  find /etc/systemd/system/ /usr/lib/systemd/system/ -type f \( -perm -777 \) -exec ls -l {} \; 2>/dev/null && echo_check "服务文件权限" "发现异常服务文件权限" "error"
}

check_suspicious_service_configurations() {
  echo_check "服务配置" "检查可疑服务配置..." "info"
  grep -rE "ExecStart.*(nc|netcat|bash.*-c|sh -c|wget|curl|telnet|perl.*-e|python.*-c|java.*-jar|ruby.*-e|python -c|perl -e|base64_decode|eval|system|passthru)" /etc/systemd/system/ /usr/lib/systemd/system/ && echo_check "服务配置" "发现可疑服务配置" "error"
}

# 数据库服务安全检查
check_database_services() {
  echo_check "数据库" "开始检查数据库服务..." "info"
  
  if command -v redis-server >/dev/null 2>&1; then
    echo_check "Redis" "服务已安装，正在检查配置..." "info"
    
    if pgrep redis-server >/dev/null 2>&1; then
      echo_check "Redis" "服务正在运行" "info"
      
      # 检查密码
      requirepass=$(redis-cli config get requirepass 2>/dev/null | awk '{print $2}')
      if [ -z "$requirepass" ]; then
        echo_check "Redis" "未设置密码，存在安全风险！" "error"
        echo_check "Redis" "请设置密码以保护 Redis 数据库。" "error"
        echo_check "Redis" "可通过修改配置文件 /etc/redis/redis.conf 设置密码。" "error"
        echo_check "Redis" "也可通过 redis-cli 命令设置密码：redis-cli config set requirepass your_password" "error"
        echo_check "Redis" "redis-cli config rewrite 可以将临时配置的密码持久化" "error"
        echo_check "Redis" "重启 Redis 服务后生效。" "error"
        echo_check "Redis" "请勿在生产环境中使用未设置密码的 Redis 服务。" "error"
      else
        echo_check "Redis" "已设置密码。" "info"
      fi
      
      # 检查绑定地址
      bind_address=$(redis-cli config get bind-address 2>/dev/null | awk '{print $2}')
      if [ "$bind_address" = "0.0.0.0" ] || [ "$bind_address" = "::" ]; then
        echo_check "Redis" "Redis 绑定到公网地址，存在安全风险！" "error"
      else
        echo_check "Redis" "Redis 绑定到本地地址，未开放公网访问。" "info"
      fi
    else
      echo_check "Redis" "服务未运行" "error"
    fi
  else
    echo_check "Redis" "服务未安装" "warning"
  fi

  if command -v mysqld >/dev/null 2>&1; then
    echo_check "MySQL" "服务存在，检查配置..." "info"
    echo_check "MySQL" "检查绑定地址..." "info"
    grep -E "^(bind-address|skip-networking)" /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/my.cnf 2>/dev/null
    echo_check "MySQL" "检查远程访问权限..." "info"
    mysql -e "SELECT user,host FROM mysql.user WHERE host NOT IN ('localhost', '127.0.0.1');" 2>/dev/null
  else
    echo_check "MySQL" "服务未安装" "warning"
  fi

  if command -v mongod >/dev/null 2>&1; then
    echo_check "MongoDB" "服务存在，检查配置..." "info"
    grep -E "^(bindIp|security.authorization)" /etc/mongod.conf 2>/dev/null
    ps -ef | grep mongod | grep -v grep | grep -E "--port|--bind_ip" 2>/dev/null
  else
    echo_check "MongoDB" "服务未安装" "warning"
  fi

  if command -v postgresql >/dev/null 2>&1; then
    echo_check "PostgreSQL" "服务运行中，检查配置..." "info"
    grep -E "^(listen_addresses|ssl)" /etc/postgresql/12/main/postgresql.conf 2>/dev/null
  else
    echo_check "PostgreSQL" "服务未安装" "warning"
  fi
}



# 基于关键词的PHP木马检查
check_webshells() {
  echo_check "WebShell检查" "开始检查WebShell文件..." "info"
  
  echo_check "WebShell检查" "检查PHP WebShell文件..." "info"
  for dir in "${WEB_DIRS[@]}"; do
    if [ -d "$dir" ]; then
      echo_check "WebShell检查" "扫描目录: $dir" "info"
      
      # 使用find命令结合-regex选项进行查找
      webshell_files=$(find "$dir" -type f -regex ".*\.\(php\|phtml\)$" 2>/dev/null | xargs grep -i -l -E "${PHP_WEBSHELL_RULES[*]}" 2>/dev/null)
      
      if [ -n "$webshell_files" ]; then
        # 过滤掉白名单路径中的文件
        for whitelist_dir in "${WHITELIST_DIRS[@]}"; do
          webshell_files=$(echo "$webshell_files" | grep -v "$whitelist_dir")
        done
        
        if [ -n "$webshell_files" ]; then
          echo_check "WebShell检查" "发现可疑PHP木马文件：" "error"
          echo "$webshell_files"
        else
          echo_check "WebShell检查" "目录 $dir 中未发现PHP木马文件。" "info"
        fi
      else
        echo_check "WebShell检查" "目录 $dir 中未发现PHP木马文件。" "info"
      fi
    else
      echo_check "WebShell检查" "目录 $dir 不存在或不可访问。" "error"
    fi
  done
}


# PHP配置文件检查
check_php_config() {
  echo_check "PHP配置" "检查PHP配置文件..." "info"

  # 检查php-cli的配置文件
  echo_check "PHP配置" "检查 PHP-CLI 配置文件:" "warning"
  check_php_cli_config

  # 检查php-fpm的配置文件
  echo_check "PHP配置" "检查 PHP-FPM 配置文件:" "warning"
  check_php_fpm_config
}

check_php_cli_config() {
  PHP_CLI_INI_PATH=$(php -i | grep "Loaded Configuration File" | awk -F"=> " '{print $2}' 2>/dev/null)
  
  if [ -f "$PHP_CLI_INI_PATH" ]; then
    echo_check "PHP-CLI配置" "PHP-CLI配置文件路径: $PHP_CLI_INI_PATH" "info"
    
    check_php_config_file "$PHP_CLI_INI_PATH"
  else
    echo_check "PHP-CLI配置" "未找到PHP-CLI配置文件，请检查PHP安装。" "warning"
  fi
}

check_php_fpm_config() {
  # 查找php-fpm.conf文件（可能有多个）
  PHP_FPM_CONF_FILES=$(sudo find / -name "php-fpm.conf" 2>/dev/null)
  
  if [ -n "$PHP_FPM_CONF_FILES" ]; then
    while read -r PHP_FPM_CONF_PATH; do
      if [ -f "$PHP_FPM_CONF_PATH" ]; then
        echo_check "PHP-FPM配置" "PHP-FPM配置文件路径: $PHP_FPM_CONF_PATH" "info"
        check_php_config_file "$PHP_FPM_CONF_PATH"
        
        # 检查PHP-FPM的池池配置文件
        echo_check "PHP-FPM配置" "检查 PHP-FPM 池池配置文件:" "warning"
        check_pool_config "$PHP_FPM_CONF_PATH"
      fi
    done <<< "$PHP_FPM_CONF_FILES"
  else
    echo_check "PHP-FPM配置" "未找到PHP-FPM配置文件，请检查PHP安装。" "warning"
  fi
}

check_pool_config() {
  MAIN_CONF=$1
  POOL_CONF_DIR=$(grep -E "^include\s*=" "$MAIN_CONF" 2>/dev/null | awk -F"=" '{print $2}' | xargs)
  
  if [ -n "$POOL_CONF_DIR" ]; then
    POOL_CONF_FILES=$(find "$POOL_CONF_DIR" -type f -name "*.conf" 2>/dev/null)
    
    while read -r POOL_CONF_PATH; do
      if [ -f "$POOL_CONF_PATH" ]; then
        echo_check "PHP-FPM池配置" "PHP-FPM池池配置文件路径: $POOL_CONF_PATH" "info"
        check_php_config_file "$POOL_CONF_PATH"
      fi
    done <<< "$POOL_CONF_FILES"
  fi
}

check_php_config_file() {
  CONFIG_FILE=$1
  echo_check "PHP配置" "检查配置文件: $CONFIG_FILE" "info"
  
  # 检查禁用的函数
  echo_check "PHP配置" "禁用的函数：" "info"
  DISABLED_FUNCTIONS=$(grep -E "^disable_functions\s*=" "$CONFIG_FILE" 2>/dev/null | awk -F"=" '{print $2}' | xargs)
  if [ -z "$DISABLED_FUNCTIONS" ]; then
    echo_check "PHP配置" "未禁用任何函数，建议禁用一些敏感函数，如：phpinfo, system, exec, shell_exec, passthru, eval, assert, create_function, preg_replace, include, require, file_get_contents, file_put_contents, fsockopen, pfsockopen, stream_socket_server, dl, highlight_file, show_source, symlink, readlink" "error"
  else
    echo "$DISABLED_FUNCTIONS"
  fi
  
  # 检查错误日志配置
  echo_check "PHP配置" "错误日志配置：" "info"
  ERROR_LOG=$(grep -E "^error_log\s*=" "$CONFIG_FILE" 2>/dev/null | awk -F"=" '{print $2}' | xargs)
  if [ -z "$ERROR_LOG" ]; then
    echo_check "PHP配置" "未配置错误日志，建议配置错误日志路径，例如：error_log = /var/log/php/error.log" "error"
  else
    echo "$ERROR_LOG"
  fi
  
  # 检查是否显示错误
  echo_check "PHP配置" "是否显示错误：" "info"
  DISPLAY_ERRORS=$(grep -E "^display_errors\s*=" "$CONFIG_FILE" 2>/dev/null | awk -F"=" '{print $2}' | xargs)
  if [ "$DISPLAY_ERRORS" = "On" ]; then
    echo_check "PHP配置" "display_errors = On，建议设置为 Off，以避免在生产环境中显示错误信息。" "error"
  else
    echo "$DISPLAY_ERRORS"
  fi
  
  # 检查其他安全选项
  echo_check "PHP配置" "其他安全选项：" "info"
  ALLOW_URL_FOPEN=$(grep -E "^allow_url_fopen\s*=" "$CONFIG_FILE" 2>/dev/null | awk -F"=" '{print $2}' | xargs)
  ALLOW_URL_INCLUDE=$(grep -E "^allow_url_include\s*=" "$CONFIG_FILE" 2>/dev/null | awk -F"=" '{print $2}' | xargs)
  if [ "$ALLOW_URL_FOPEN" = "On" ]; then
    echo_check "PHP配置" "allow_url_fopen = On，建议设置为 Off，以防止远程文件包含漏洞。" "error"
  else
    echo "allow_url_fopen = $ALLOW_URL_FOPEN"
  fi
  if [ "$ALLOW_URL_INCLUDE" = "On" ]; then
    echo_check "PHP配置" "allow_url_include = On，建议设置为 Off，以防止远程文件包含漏洞。" "error"
  else
    echo "allow_url_include = $ALLOW_URL_INCLUDE"
  fi
}

# 数据库开放端口检查
check_database_ports() {
  echo_check "数据库端口" "检查数据库端口暴露情况..." "info"
  ss -tulnp | grep -E ":(6379|3306|27017|5432)" 2>/dev/null && echo_check "数据库端口" "数据库端口暴露。" "error"
}

# 文件和用户检查
check_sensitive_file_permissions() {
  echo_check "文件权限" "检查敏感文件权限..." "info"

  find /etc/ -type f \( -name "passwd" -o -name "shadow" -o -name "sudoers" \) -exec ls -l {} \; 2>/dev/null | awk '{ if ($1 ~ /^(rw-r--r--|rw-r-----|r--r-----|r--r--r--)$/ && ($9 ~ /^\/etc\/(passwd|shadow|sudoers)$/)) { print "\033[0;31m权限异常：\033[0m" $9, "权限：" $1 } }'
}

check_suid_sgid_files() {
  echo_check "SUID/SGID文件" "检查 SUID/SGID 文件..." "info"
  find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null && echo_check "SUID/SGID文件" "发现SUID/SGID文件，请检查是否必要。" "warning"
}



check_recent_user_group_changes() {
  echo_check "用户和组变更" "检查新创建的用户和组..." "info"
  
  # 定义日志文件路径
  LOG_FILE=""
  if [ "$SYSTEM_TYPE" = "debian" ]; then
    LOG_FILE="/var/log/auth.log"
  elif [ "$SYSTEM_TYPE" = "redhat" ]; then
    LOG_FILE="/var/log/secure"
  else
    echo_check "用户和组变更" "不支持的操作系统类型: $SYSTEM_TYPE" "error"
    return
  fi

  # 检查日志文件是否存在
  if [ ! -f "$LOG_FILE" ]; then
    echo_check "用户和组变更" "日志文件 $LOG_FILE 不存在，可能需要手动检查。" "warning"
    return
  fi

  echo_check "用户和组变更" "最近修改的用户: " "info"
  # 过滤用户创建和修改的事件
  grep -E "useradd|usermod|chpasswd|passwd" "$LOG_FILE" 2>/dev/null | tail -n 10

  echo_check "用户和组变更" "最近修改的组: " "info"
  # 过滤组创建和修改的事件
  grep -E "groupadd|groupmod" "$LOG_FILE" 2>/dev/null | tail -n 10

  echo_check "用户和组变更" "最近修改的密码: " "info"
  # 过滤密码修改的事件
  grep -E "passwd" "$LOG_FILE" 2>/dev/null | tail -n 10
}

# NFS共享检查
check_nfs() {
  echo_check "NFS共享" "检查NFS共享..." "info"
  showmount -e localhost 2>/dev/null && echo_check "NFS共享" "NFS共享配置异常。" "error"
}

# 综合检查firewalld, iptables, ufw等防火墙配置
check_firewall() {
  echo_check "防火墙" "检查防火墙配置..." "info"

  if command -v firewalld >/dev/null 2>&1; then
    echo_check "firewalld" "服务存在，检查配置..." "info"
    firewall-cmd --list-ports --list-services
    firewall-cmd --list-all-zones
  else
    echo_check "firewalld" "服务未安装" "error"
  fi

  if command -v iptables >/dev/null 2>&1; then
    echo_check "iptables" "服务存在，检查配置..." "info"
    iptables -L -n -v | column -t
    default_policy=$(iptables -L -n -v | grep "Chain" | awk '{print $2 " " $3}')
    if [ -n "$default_policy" ]; then
      echo_check "iptables" "$default_policy" "info"
    else
      echo_check "iptables" "无法获取默认策略，请手动检查。" "error"
    fi

    if [ "$SYSTEM_TYPE" = "debian" ]; then
      if [ -f /etc/iptables/rules.v4 ]; then
        echo_check "iptables" "找到配置文件: /etc/iptables/rules.v4" "info"
        cat /etc/iptables/rules.v4
      else
        echo_check "iptables" "未找到 iptables-persistent 配置文件。" "warning"
      fi

      if command -v ufw >/dev/null 2>&1; then
        ufw status verbose
      else
        echo_check "ufw" "未安装或未启用。" "warning"
      fi
    elif [ "$SYSTEM_TYPE" = "redhat" ]; then
      if [ -f /etc/sysconfig/iptables ]; then
        echo_check "iptables" "找到配置文件: /etc/sysconfig/iptables" "info"
        cat /etc/sysconfig/iptables
      else
        echo_check "iptables" "未找到 /etc/sysconfig/iptables 配置文件。" "warning"
      fi
    else
      echo_check "iptables" "未知系统类型，无法确定 iptables 配置文件路径。" "warning"
    fi
  else
    echo_check "iptables" "服务未安装" "error"
  fi

  if command -v ufw >/dev/null 2>&1; then
    echo_check "ufw" "服务存在，检查配置..." "info"
    ufw status verbose
    grep 'DEFAULT' /etc/ufw/ufw.conf 2>/dev/null
  else
    echo_check "ufw" "服务未安装" "error"
  fi
}

# 检查SSH服务配置和授权，确认登录方式
check_ssh_service() {
  echo_check "SSH服务" "检查 SSH 服务状态..." "info"

  if systemctl list-unit-files --full -all | grep -q "sshd.service"; then
    echo_check "SSH服务" "服务存在。" "info"
    if systemctl is-active --quiet sshd; then
      echo_check "SSH服务" "服务已开启。" "info"
      return 0
    else
      echo_check "SSH服务" "服务未开启。" "error"
      return 1
    fi
  else
    echo_check "SSH服务" "服务不存在。" "error"
    return 2
  fi
}

check_ssh_config() {
  echo_check "SSH配置" "检查 SSH 配置文件..." "info"
  echo_check "SSH配置" "配置文件路径: /etc/ssh/sshd_config" "info"
  cat /etc/ssh/sshd_config | grep -E "^(#)?(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AuthorizedKeysFile|ListenAddress|MaxAuthTries)" | grep -vE "^#"
}

check_ssh_login_methods() {
  echo_check "SSH登录方式" "检查 SSH 登录方式..." "info"

  echo_check "SSH登录方式" "检查是否允许密码认证：" "info"
  if grep -qE "^PasswordAuthentication\s+no" /etc/ssh/sshd_config; then
    echo_check "SSH登录方式" "密码认证已禁用。" "info"
  elif grep -qE "^PasswordAuthentication" /etc/ssh/sshd_config; then
    echo_check "SSH登录方式" "密码认证未禁用。" "error"
  else
    echo_check "SSH登录方式" "密码认证配置未明确设置，使用默认值（默认允许）。" "warning"
  fi

  echo_check "SSH登录方式" "检查是否允许公钥认证：" "info"

}

# SSH检查函数调用逻辑
check_ssh_service_status() {
  check_ssh_service
  case $? in
    0)
      check_ssh_config
      check_ssh_login_methods
      ;;
    1)
      echo_check "SSH" "服务未开启，跳过后续 SSH 检查。" "warning"
      ;;
    2)
      echo_check "SSH" "服务不存在，跳过后续 SSH 检查。" "warning"
      ;;
    *)
      echo_check "SSH" "未知错误，无法确定 SSH 服务状态。" "error"
      ;;
  esac
}

# 系统完整性检查
check_system_integrity() {
  echo_check "System" "[+] 检查系统文件完整性..." "info"

  if command -v rpm >/dev/null 2>&1; then
    rpm_output=$(rpm -Va 2>/dev/null | grep -E "c M|S.5")
    if [ -n "$rpm_output" ]; then
      echo_check "System" "检测到系统文件完整性问题（RPM 系统）：" "warning"
      echo_check "System" "$rpm_output" "warning"
    fi
  fi

  if command -v dpkg >/dev/null 2>&1; then
    dpkg_output=$(dpkg --verify 2>/dev/null | grep "mtime changed")
    if [ -n "$dpkg_output" ]; then
      echo_check "System" "检测到系统文件完整性问题（Debian 系统）：" "warning"
      echo_check "System" "$dpkg_output" "warning"
    fi
  fi

  if command -v tripwire >/dev/null 2>&1; then
    echo_check "System" "正在运行 Tripwire 文件完整性检查..." "info"
    tripwire -m c 2>/dev/null
  elif command -v aide >/dev/null 2>&1; then
    echo_check "System" "正在运行 AIDE 文件完整性检查..." "info"
    aide --check 2>/dev/null
  else
    echo_check "System" "未找到文件完整性检查工具，请安装 Tripwire 或 AIDE。" "warning"
  fi
}

# 内核加载项检查
check_kernel_parameters() {
  echo_check "Kernel" "[+] 检查内核参数..." "info"

  sysctl_output=$(sysctl -a 2>/dev/null | grep -E "net.ipv4.conf.all.accept_source_route|net.ipv4.conf.default.accept_source_route|net.ipv4.tcp_syncookies")
  if [ -n "$sysctl_output" ]; then
    echo_check "Kernel" "检测到内核参数配置问题：" "warning"
    echo_check "Kernel" "$sysctl_output" "warning"
  else
    echo_check "Kernel" "未检测到内核参数配置问题" "info"
  fi
}

# 自动修复常见敏感文件权限
fix_sensitive_file_permissions() {
  echo_check "Permissions" "[+] 自动修复敏感文件权限..." "info"
  chmod 644 /etc/passwd 2>/dev/null
  chmod 600 /etc/shadow 2>/dev/null
}



# 检查Fail2Ban配置文件与日志
check_fail2ban() {
  echo_check "Fail2Ban" "[+] 检查 Fail2Ban 配置文件..." "info"

  fail2ban_config=$(find /etc /usr/local -type f -name "fail2ban*.conf" -o -name "fail2ban*.d/*.conf" 2>/dev/null | head -n 1)
  if [ -n "$fail2ban_config" ]; then
    echo_check "Fail2Ban" "找到 Fail2Ban 配置文件: $fail2ban_config" "info"
    grep -E "logtarget|bantime|maxretry" "$fail2ban_config"
  else
    echo_check "Fail2Ban" "未找到 Fail2Ban 配置文件" "error"
  fi

  echo_check "Fail2Ban" "[+] 检查 Fail2Ban 日志文件..." "info"

  log_target=$(find /var/log -type f -name "fail2ban*.log" 2>/dev/null | head -n 1)
  if [ -n "$log_target" ] && [ -f "$log_target" ]; then
    echo_check "Fail2Ban" "找到 Fail2Ban 日志文件: $log_target" "info"
    grep "Ban" "$log_target" | tail -n 10
  else
    echo_check "Fail2Ban" "未找到 Fail2Ban 日志文件" "warning"
  fi
}

# 检查HTTP服务（OpenResty/Caddy/Nginx/Apache）的配置与日志
check_http_services() {
  echo_check "HTTP" "[+] 检查 HTTP 服务配置文件和日志文件..." "info"

  if command -v caddy >/dev/null 2>&1; then
    check_caddy
  fi

  if command -v nginx >/dev/null 2>&1; then
    check_nginx
  fi

  if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
    check_apache
  fi
}

# 检查 Caddy 配置文件和日志
check_caddy() {
  echo_check "Caddy" "[+] 检查 Caddy 配置文件..." "info"

  caddy_configs=$(find /etc /usr/local /www -type f -name "Caddyfile" -o -name "caddy*.conf" 2>/dev/null)
  if [ -z "$caddy_configs" ]; then
    echo_check "Caddy" "未找到 Caddy 主配置文件" "error"
    return
  fi

  echo_check "Caddy" "找到 Caddy 配置文件：" "info"
  echo "$caddy_configs"

  extract_logs() {
    local config_file="$1"
    local log_paths=()
    while IFS= read -r line; do
      if [[ "$line" =~ ^\s*include\s+ ]]; then
        local include_path=$(echo "$line" | grep -oP '\K\S+(?=;)')
        if [ -d "$include_path" ]; then
          for file in "$include_path"/*; do
            if [ -f "$file" ]; then
              log_paths+=($(extract_logs "$file"))
            fi
          done
        elif [ -f "$include_path" ]; then
          log_paths+=($(extract_logs "$include_path"))
        fi
      elif [[ "$line" =~ ^\s*access_log\s+ ]]; then
        local log_path=$(echo "$line" | grep -oP 'access_log[ ]+\K\S+(?=;)')
        if [[ "$log_path" =~ \.log$ ]]; then
          log_paths+=("$log_path")
        fi
      elif [[ "$line" =~ ^\s*error_log\s+ ]]; then
        local log_path=$(echo "$line" | grep -oP 'error_log[ ]+\K\S+(?=;)')
        if [[ "$log_path" =~ \.log$ ]]; then
          log_paths+=("$log_path")
        fi
      fi
    done < "$config_file"
    echo "${log_paths[@]}"
  }

  all_access_logs=()
  all_error_logs=()
  for config_file in $caddy_configs; do
    all_access_logs+=($(extract_logs "$config_file" | grep -E 'access.*\.log'))
    all_error_logs+=($(extract_logs "$config_file" | grep -E 'error.*\.log'))
  done

  all_access_logs=($(echo "${all_access_logs[@]}" | tr ' ' '\n' | sort -u))
  all_error_logs=($(echo "${all_error_logs[@]}" | tr ' ' '\n' | sort -u))

  echo_check "Caddy" "[+] 检查 Caddy 日志文件..." "info"

  if [ ${#all_access_logs[@]} -gt 0 ]; then
    echo_check "Caddy" "[+] 找到的 Caddy 访问日志文件：" "info"
    for log_file in "${all_access_logs[@]}"; do
      if [ -f "$log_file" ]; then
        echo_check "Caddy" "  - $log_file" "info"
        tail -n 10 "$log_file"
      else
        echo_check "Caddy" "  - 未找到日志文件: $log_file" "error"
      fi
    done
  else
    echo_check "Caddy" "未找到 Caddy 访问日志文件" "error"
  fi

  if [ ${#all_error_logs[@]} -gt 0 ]; then
    echo_check "Caddy" "[+] 找到的 Caddy 错误日志文件：" "info"
    for log_file in "${all_error_logs[@]}"; do
      if [ -f "$log_file" ]; then
        echo_check "Caddy" "  - $log_file" "info"
        tail -n 10 "$log_file"
      else
        echo_check "Caddy" "  - 未找到日志文件: $log_file" "error"
      fi
    done
  else
    echo_check "Caddy" "未找到 Caddy 错误日志文件" "error"
  fi

  if [ ${#all_access_logs[@]} -gt 0 ]; then
    echo_check "Caddy" "[+] 分析 Caddy 访问日志中的请求数量过大的 IP..." "info"
    for log_file in "${all_access_logs[@]}"; do
      if [ -f "$log_file" ]; then
        echo_check "Caddy" "  - 分析日志文件: $log_file" "info"
        grep -oE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})' "$log_file" | sort | uniq -c | sort -nr | head -n 10
      else
        echo_check "Caddy" "  - 未找到日志文件: $log_file" "error"
      fi
    done
  fi

  if [ ${#all_access_logs[@]} -gt 0 ]; then
    echo_check "Caddy" "[+] 分析 Caddy 日志中的 404 错误过多的 IP..." "info"
    for log_file in "${all_access_logs[@]}"; do
      if [ -f "$log_file" ]; then
        echo_check "Caddy" "  - 分析日志文件: $log_file" "info"
        grep " 404 " "$log_file" | grep -oE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})' | sort | uniq -c | sort -nr | head -n 10
      else
        echo_check "Caddy" "  - 未找到日志文件: $log_file" "error"
      fi
    done
  fi
}

# 检查 Nginx 配置文件和日志
check_nginx() {
    echo_check "Nginx" "[+] 检查 Nginx 配置文件..." "info"

    # 查找可能的 Nginx 配置文件路径
    mapfile -t nginx_configs < <(find /etc/nginx /usr/local/nginx/conf /www/server -maxdepth 3 -type f \( -name "nginx*.conf" -o -name "httpd*.conf" \) 2>/dev/null)

    # 检查日志文件并输出内容
    check_log_files() {
        local log_files=("$@")
        local log_file

        if [ ${#log_files[@]} -gt 0 ]; then
            for log_file in "${log_files[@]}"; do
                if [[ -f "$log_file" ]]; then
                    echo -e "${GREEN}  - $log_file${NC}"
                else
                   echo_check "Nginx" "[!]  - 日志文件不存在: $log_file" "warning"
                fi
            done
        else
           echo_check "Nginx" "[!]  - 未找到日志文件" "warning"
        fi
    }

    # 提取日志路径的通用函数
    extract_log_paths() {
        local config_file="$1"
        local current_dir=$(dirname "$config_file")
        local log_paths=()

        # 声明为关联数组
        declare -A processed_files

        # 确保 config_file 不为空
        if [[ -z "$config_file" ]]; then
            echo_check "Nginx" "[!]  - 未找到配置文件" "warning"
            return
        fi

        # 检查是否已经处理过该文件
        if [[ -n "${processed_files["$config_file"]}" ]]; then
            return
        fi

        processed_files["$config_file"]=1

        # 检查并读取配置文件
        if [[ ! -f "$config_file" ]]; then
            echo_check "Nginx" "[!]  - 配置文件不存在: $config_file" "warning"
            return
        fi

        while IFS= read -r line || [[ -n "$line" ]]; do
            line=$(echo "$line" | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            [[ -z "$line" ]] && continue

            if [[ "$line" =~ ^include ]]; then
                include_pattern=$(echo "$line" | awk '{print $2}' | sed 's/;//')
                include_pattern=${include_pattern# }

                # 处理相对路径
                if [[ "$include_pattern" != /* ]]; then
                    include_pattern="${current_dir}/${include_pattern}"
                fi

                # 检查是否包含通配符
                shopt -s nullglob
                included_files=($include_pattern)
                shopt -u nullglob

                for included_file in "${included_files[@]}"; do
                    if [[ -f "$included_file" ]]; then
                        log_paths+=($(extract_log_paths "$included_file"))
                    fi
                done

            elif [[ "$line" =~ ^access_log ]]; then
                log_path=$(echo "$line" | awk '{print $2}' | sed 's/;//' | sed 's/["'"'"']//g')
                [[ "$log_path" != off ]] && log_paths+=("$log_path")

            elif [[ "$line" =~ ^error_log ]]; then
                log_path=$(echo "$line" | awk '{print $2}' | sed 's/;//' | sed 's/["'"'"']//g')
                [[ "$log_path" != off ]] && log_paths+=("$log_path")
            fi
        done < "$config_file"

        # 去重并返回结果
        printf "%s\n" "${log_paths[@]}" | awk '!seen[$0]++'
    }

    if [ ${#nginx_configs[@]} -eq 0 ]; then
        echo_check "Nginx" "[!]  - 未找到 Nginx 主配置文件" "warning"
        return
    fi

    echo_check "Nginx" "[+] 找到 Nginx 配置文件：" "info"
    printf "  - %s\n" "${nginx_configs[@]}"

    local all_logs=()
    local error_logs=()
    local access_logs=()

    for config_file in "${nginx_configs[@]}"; do
        extracted_logs=$(extract_log_paths "$config_file")
        all_logs+=($(grep -E '.*\.log$' <<< "$extracted_logs"))
        error_logs+=($(grep -E 'error\.log$' <<< "$extracted_logs"))
    done

    # 去重
    all_logs=($(printf "%s\n" "${all_logs[@]}" | sort -u))
    error_logs=($(printf "%s\n" "${error_logs[@]}" | sort -u))

    # 计算访问日志 = 全部日志 - 错误日志
    access_logs=($(comm -23 <(printf "%s\n" "${all_logs[@]}" | sort) <(printf "%s\n" "${error_logs[@]}" | sort)))

    echo_check "Nginx" "[+] 检查 Nginx 访问日志文件..." "info"
    check_log_files "${access_logs[@]}"

    echo_check "Nginx" "[+] 检查 Nginx 错误日志文件..." "info"
    check_log_files "${error_logs[@]}"
}


# 检查 Apache 配置文件和日志
check_apache() {
  echo_check "Apache" "[+] 检查 Apache 配置文件..." "info"

  apache_configs=$(find /etc /usr/local /www -type f -name "apache*.conf" -o -name "httpd*.conf" 2>/dev/null)
  if [ -z "$apache_configs" ]; then
    echo_check "Apache" "未找到 Apache 主配置文件" "error"
    return
  fi

  echo_check "Apache" "找到 Apache 配置文件：" "info"
  echo "$apache_configs"

  extract_logs() {
    local config_file="$1"
    local log_paths=()
    while IFS= read -r line; do
      if [[ "$line" =~ ^\s*Include\s+ ]]; then
        local include_path=$(echo "$line" | grep -oP '\K\S+(?=;)')
        if [ -d "$include_path" ]; then
          for file in "$include_path"/*; do
            if [ -f "$file" ]; then
              log_paths+=($(extract_logs "$file"))
            fi
          done
        elif [ -f "$include_path" ]; then
          log_paths+=($(extract_logs "$include_path"))
        fi
      elif [[ "$line" =~ ^\s*CustomLog\s+ ]]; then
        local log_path=$(echo "$line" | grep -oP 'CustomLog[ ]+\K\S+(?=;)')
        if [[ "$log_path" =~ \.log$ ]]; then
          log_paths+=("$log_path")
        fi
      elif [[ "$line" =~ ^\s*ErrorLog\s+ ]]; then
        local log_path=$(echo "$line" | grep -oP 'ErrorLog[ ]+\K\S+(?=;)')
        if [[ "$log_path" =~ \.log$ ]]; then
          log_paths+=("$log_path")
        fi
      fi
    done < "$config_file"
    echo "${log_paths[@]}"
  }

  all_access_logs=()
  all_error_logs=()
  for config_file in $apache_configs; do
    all_access_logs+=($(extract_logs "$config_file" | grep -E 'access.*\.log'))
    all_error_logs+=($(extract_logs "$config_file" | grep -E 'error.*\.log'))
  done

  all_access_logs=($(echo "${all_access_logs[@]}" | tr ' ' '\n' | sort -u))
  all_error_logs=($(echo "${all_error_logs[@]}" | tr ' ' '\n' | sort -u))

  echo_check "Apache" "[+] 检查 Apache 日志文件..." "info"

  if [ ${#all_access_logs[@]} -gt 0 ]; then
    echo_check "Apache" "[+] 找到的 Apache 访问日志文件：" "info"
    for log_file in "${all_access_logs[@]}"; do
      if [ -f "$log_file" ]; then
        echo_check "Apache" "  - $log_file" "info"
        tail -n 10 "$log_file"
      else
        echo_check "Apache" "  - 未找到日志文件: $log_file" "error"
      fi
    done
  else
    echo_check "Apache" "未找到 Apache 访问日志文件" "error"
  fi

  if [ ${#all_error_logs[@]} -gt 0 ]; then
    echo_check "Apache" "[+] 找到的 Apache 错误日志文件：" "info"
    for log_file in "${all_error_logs[@]}"; do
      if [ -f "$log_file" ]; then
        echo_check "Apache" "  - $log_file" "info"
        tail -n 10 "$log_file"
      else
        echo_check "Apache" "  - 未找到日志文件: $log_file" "error"
      fi
    done
  else
    echo_check "Apache" "未找到 Apache 错误日志文件" "error"
  fi

  if [ ${#all_access_logs[@]} -gt 0 ]; then
    echo_check "Apache" "[+] 分析 Apache 访问日志中的请求数量过大的 IP..." "info"
    for log_file in "${all_access_logs[@]}"; do
      if [ -f "$log_file" ]; then
        echo_check "Apache" "  - 分析日志文件: $log_file" "info"
        grep -oE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})' "$log_file" | sort | uniq -c | sort -nr | head -n 10
      else
        echo_check "Apache" "  - 未找到日志文件: $log_file" "error"
      fi
    done
  fi

  if [ ${#all_access_logs[@]} -gt 0 ]; then
    echo_check "Apache" "[+] 分析 Apache 日志中的 404 错误过多的 IP..." "info"
    for log_file in "${all_access_logs[@]}"; do
      if [ -f "$log_file" ]; then
        echo_check "Apache" "  - 分析日志文件: $log_file" "info"
        grep " 404 " "$log_file" | grep -oE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.9>+|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})' | sort | uniq -c | sort -nr | head -n 10
        else
          echo_check "Apache" "  - 未找到日志文件: $log_file" "error"
        fi
      done
    fi
}

# 登录日志审计
check_login_audit() {
  echo_check "Login" "[+] 检查登录日志..." "info"
  echo -e "================================"

  echo_check "Login" "[+] 检查成功登录尝试..." "info"
  if [ "$SYSTEM_TYPE" = "debian" ]; then
    grep "Accepted" /var/log/auth.log* 2>/dev/null |
    awk -F'[ :]+' '{for (i=1; i<=NF; i++) if ($i ~ /^(from|by)$/) {print $(i+1)}}' |
    grep -oE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})' |
    sort | uniq -c | sort -nr | head -n 15
  elif [ "$SYSTEM_TYPE" = "redhat" ]; then
    grep "Accepted" /var/log/secure* 2>/dev/null |
    awk -F'[ :]+' '{for (i=1; i<=NF; i++) if ($i ~ /^(from|by)$/) {print $(i+1)}}' |
    grep -oE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})' |
    sort | uniq -c | sort -nr | head -n 15
  fi

  echo_check "Login" "[+] 检查失败登录尝试..." "info"
  if [ "$SYSTEM_TYPE" = "debian" ]; then
    grep "Failed password" /var/log/auth.log* 2>/dev/null |
    awk -F'[ :]+' '{for (i=1; i<=NF; i++) if ($i ~ /^(from|by)$/) {print $(i+1)}}' |
    grep -oE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})' |
    sort | uniq -c | sort -nr | head -n 15
  elif [ "$SYSTEM_TYPE" = "redhat" ]; then
    grep "Failed password" /var/log/secure* 2>/dev/null |
    awk -F'[ :]+' '{for (i=1; i<=NF; i++)	if ($i ~ /^(from|by)$/) {print $(i+1)}}' |
    grep -oE '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})' |
    sort | uniq -c | sort -nr | head -n 15
  fi
}

# 检查最近修改/创建的文件
check_unknown_files() {
  echo_check "Files" "[+] 检查最近修改的文件..." "info"
echo -e "================================"
  find / -type f -mtime -1 -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -exec stat --format="%Y %n" {} \; 2>/dev/null | sort -nr | head -n 20 | while read timestamp filename; do ls -l --time=birth "$filename"; done
}

# 定时任务和计划任务的审计
check_cron_jobs() {
  echo_check "Cron" "[+] 检查定时任务..." "info"
  echo -e "================================"

  declare -a SECURITY_KEYWORDS=(
    "rm -rf"
    "chmod"
    "wget"
    "curl"
    "base64"
    "python"
    "sh -c"
    "bash -c"
    "dd "
    "mkfs"
    "mount"
  )

  security_audit() {
    local source=$1
    shift
    local content=$@
    local AUDIT_RESULTS=()
    local line_number=0

    while IFS= read -r line; do
      line_number=$((line_number + 1))
      for keyword in "${SECURITY_KEYWORDS[@]}"; do
        if [[ "$line" =~ $keyword ]]; then
          AUDIT_RESULTS+=("$source: Line $line_number: $line")
          break
        fi
      done
    done <<< "$content"

    if [ "${#AUDIT_RESULTS[@]}" -gt 0 ]; then
      echo_check "Cron" "[!] 发现匹配的安全审计关键词:" "error"
      for result in "${AUDIT_RESULTS[@]}"; do
        echo_check "Cron" "$result" "warning"
      done
    fi
  }

  echo_check "Cron" "[+] 正在审计:全局定时任务" "info"
  GLOBAL_CRON_OUTPUT=$(cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v -E '^\s*$')
  security_audit "全局定时任务" "$GLOBAL_CRON_OUTPUT"

  echo_check "Cron" "[+] 正在审计:用户定时任务" "info"
  USER_CRON_OUTPUT=$(crontab -l 2>/dev/null)
  security_audit "用户定时任务" "$USER_CRON_OUTPUT"

  echo_check "Cron" "[+] 正在审计:系统定时任务" "info"
  SYSTEM_CRON_OUTPUT=$(find /etc/cron.* /var/spool/cron -type f -exec cat {} \; 2>/dev/null | grep -v '^#' | grep -v -E '^\s*$')
  security_audit "系统定时任务" "$SYSTEM_CRON_OUTPUT"
}

# 文件完整性检查
check_file_integrity() {
  echo_check "Integrity" "[+] 检查文件完整性..." "info"
  echo -e "================================"

  echo_check "Integrity" "[+] 检查关键文件的完整性:" "info"
  if command -v tripwire >/dev/null 2>&1; then
    tripwire -m c 2>/dev/null
  elif command -v aide >/dev/null 2>&1; then
    aide --check 2>/dev/null
  else
    echo_check "Integrity" "未找到文件完整性检查工具，请安装 Tripwire 或 AIDE。" "error"
  fi
}

# 检查系统更新和补丁
check_system_updates() {
  echo_check "Updates" "[+] 检查系统更新和补丁..." "info"
  echo -e "================================"

  if command -v yum >/dev/null 2>&1; then
    echo_check "Updates" "[+] 检查 YUM 更新:" "info"
    yum check-update 2>/dev/null | grep -q 'updates' && echo_check "Updates" "系统有待更新的软件包。" "error"
  elif command -v apt >/dev/null 2>&1; then
    echo_check "Updates" "[+] 检查 APT 更新:" "info"
    apt list --upgradable 2>/dev/null | grep -q 'upgradable' && echo_check "Updates" "系统有待更新的软件包。" "error"
  elif command -v zypper >/dev/null 2>&1; then
    echo_check "Updates" "[+] 检查 Zypper 更新:" "info"
    zypper list-updates 2>/dev/null | grep -q 'updates' && echo_check "Updates" "系统有待更新的软件包。" "error"
  else
    echo_check "Updates" "未找到支持的包管理器，请手动检查系统更新。" "error"
  fi
}

# 检查用户和组权限
check_user_group_permissions() {
  echo_check "Permissions" "[+] 检查用户和组权限..." "info"
  echo -e "================================"

  echo_check "Permissions" "[+] 检查用户和组:" "info"
  cat /etc/passwd | awk -F: '{print $1, $3, $4, $6}' | while read user uid gid home; do
    if [ -d "$home" ] && [ -n "$(ls -A "$home")" ]; then
      echo_check "Permissions" "  - 用户: $user (UID: $uid, GID: $gid, 主目录: $home)" "info"
    fi
  done

  echo_check "Permissions" "[+] 检查 Sudo 权限:" "info"
  if [ -f /etc/sudoers ]; then
    grep -v '^#' /etc/sudoers | grep -v -E '^\s*$'
  else
    echo_check "Permissions" "未找到 Sudo 配置文件。" "warning"
  fi
}

# 检查网络连接和端口
check_network_connections() {
  echo_check "Network" "[+] 检查网络连接和端口..." "info"
  echo -e "================================"

  echo_check "Network" "[+] 列出所有网络连接:" "info"
  ss -tulnp

  echo_check "Network" "[+] 列出所有开放端口:" "info"
  netstat -tuln
}

# 检查日志文件权限
check_log_file_permissions() {
  echo_check "LogFiles" "[+] 检查日志文件权限..." "info"
  echo -e "================================"

  echo_check "LogFiles" "[+] 检查 /var/log 目录权限:" "info"
  var_log_permissions=$(ls -ld /var/log)
  echo "$var_log_permissions"

  var_log_perm=$(echo "$var_log_permissions" | awk '{print $1}')
  if [[ "$var_log_perm" == "-rw-r-----" || "$var_log_perm" == "drwxr-x---" ]]; then
    echo_check "LogFiles" "权限符合标准: $var_log_perm" "info"
  else
    echo_check "LogFiles" "权限不符合标准: $var_log_perm (建议权限: drwxr-x--- 或 -rw-r-----)" "error"
  fi

  check_log_file() {
    local log_file="$1"
    local expected_perm="$2"
    if [ -f "$log_file" ]; then
      local log_permissions=$(ls -l "$log_file")
      echo "$log_permissions"
      local log_perm=$(echo "$log_permissions" | awk '{print $1}')
      if [[ "$log_perm" == "$expected_perm" ]]; then
        echo_check "LogFiles" "权限符合标准: $log_perm" "info"
      else
        echo_check "LogFiles" "权限不符合标准: $log_perm (建议权限: $expected_perm)" "error"
      fi
    else
      echo_check "LogFiles" "日志文件不存在: $log_file" "warning"
    fi
  }

  check_log_file "/var/log/auth.log" "-rw-r-----"
}

# 检查 SELinux/AppArmor 状态
check_selinux_apparmor() {
  echo_check "SELinux/AppArmor" "[+] 检查 SELinux/AppArmor 状态..." "info"
  echo -e "================================"

  if command -v sestatus >/dev/null 2>&1; then
    echo_check "SELinux" "[+] SELinux 状态:" "info"
    sestatus_output=$(sestatus)
    if echo "$sestatus_output" | grep -q "Current mode:.*enforcing"; then
      echo_check "SELinux" "SELinux 正常运行（模式：Enforcing）" "info"
    else
      echo_check "SELinux" "[!] SELinux 未处于 Enforcing 模式，可能存在安全风险！" "error"
    fi
  else
    echo_check "SELinux" "[!] SELinux 未安装或不可用" "warning"
  fi

  if command -v aa-status >/dev/null 2>&1; then
    echo_check "AppArmor" "[+] AppArmor 状态:" "info"
    aa_status_output=$(aa-status)
    if echo "$aa_status_output" | grep -q "profiles are in enforce mode"; then
      echo_check "AppArmor" "AppArmor 正常运行（有强制模式的配置文件）" "info"
    else
      echo_check "AppArmor" "[!] AppArmor 未启用强制模式的配置文件，可能存在安全风险！" "error"
    fi
  else
    echo_check "AppArmor" "[!] AppArmor 未安装或不可用" "warning"
  fi
}

# 检查系统服务状态
check_system_services() {
  echo_check "Services" "[+] 检查系统服务状态..." "info"
  echo -e "================================"

  echo_check "Services" "[+] 列出所有运行中的服务:" "info"
  systemctl list-units --type=service --state=running 2>/dev/null
}

# 检查系统启动项
check_system_boot_entries() {
    declare -a SECURITY_KEYWORDS=(
        "rm -rf"
        "chmod"
        "wget"
        "curl"
        "base64"
        "python"
        "sh -c"
        "bash -c"
        "dd "
        "mkfs"
        "mount"
    )
  echo_check "BootEntries" "[+] 检查系统启动项..." "info"
  echo -e "================================"

  local has_issues=0
  local service_files=$(systemctl list-unit-files --type=service --state=enabled,static,masked 2>/dev/null | awk '{print $1}' | grep -v '^#')

  for service in $service_files; do
    # 获取服务文件路径
    local service_path=$(systemctl show "$service" -p FragmentPath --no-pager 2>/dev/null | awk -F'=' '{print $2}')
    
    # 如果服务文件路径无效或文件不存在，则跳过
    if [ -z "$service_path" ] || [ ! -f "$service_path" ]; then
      # echo -e "${YELLOW}[!] 无法获取或访问服务文件路径: $service${NC}"
      continue
    fi

    # 获取服务文件内容
    local service_content=$(cat "$service_path" 2>/dev/null)
    
    # 提取 ExecStart= 后的内容
    local exec_start_line=$(echo "$service_content" | grep -m1 'ExecStart=' | sed 's/ExecStart=//' | xargs)

    # 如果 exec_start_line 不为空，则进行关键词审计
    if [ -n "$exec_start_line" ]; then
      for keyword in "${SECURITY_KEYWORDS[@]}"; do
        if [[ "$exec_start_line" == *"$keyword"* ]]; then
          has_issues=1
          echo_check "BootEntries" "[!] 安全审计警告: 服务 $service 包含关键词 '$keyword'" "error"
          echo_check "BootEntries" "[$service] ExecStart= $exec_start_line" "warning"
          echo_check "BootEntries" "查看启动项详细信息的命令: systemctl cat $service" "info"
          break
        fi
      done
    fi
  done

  # 如果未发现问题
  if [ $has_issues -eq 0 ]; then
    echo_check "BootEntries" "[+] 未发现明显的安全问题。" "info"
  fi
}

# 检查系统时间同步
check_system_time_synchronization() {
  echo_check "TimeSync" "[+] 检查系统时间同步..." "info"
  echo -e "================================"

  if command -v chronyc >/dev/null 2>&1; then
    echo_check "Chrony" "[+] Chrony 时间同步状态:" "info"
    if chronyc tracking 2>/dev/null | grep -q "Reference ID"; then
      echo_check "Chrony" "时间同步正常。" "info"
    else
      echo_check "Chrony" "时间同步异常，请检查 Chrony 配置。" "error"
    fi
  elif command -v ntpq >/dev/null 2>&1; then
    echo_check "NTP" "[+] NTP 时间同步状态:" "info"
    if ntpq -p 2>/dev/null | grep -q "^\*"; then
      echo_check "NTP" "时间同步正常。" "info"
    else
      echo_check "NTP" "时间同步异常，请检查 NTP 配置。" "error"
    fi
  else
    echo_check "TimeSync" "未找到时间同步服务，请检查系统时间同步配置。" "error"
  fi
}



# 用户信息检查
check_user_information() {
  echo_check "User Info" "[+] 检查用户信息..." "info"
  echo -e "================================"

  echo_check "User Info" "[+] 检查是否存在超级用户（UID=0的用户）..." "info"
  super_users=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
  if [ -n "$super_users" ]; then
    echo_check "User Info" "发现超级用户: $super_users" "error"
  else
    echo_check "User Info" "未发现超级用户。" "info"
  fi

  echo_check "User Info" "[+] 检查是否存在空口令账户..." "info"
  empty_password_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
  if [ -n "$empty_password_users" ]; then
    echo_check "User Info" "发现空口令账户: $empty_password_users" "error"
  else
    echo_check "User Info" "未发现空口令账户。" "info"
  fi

  echo_check "User Info" "[+] 检查是否存在新增用户（UID >= 1000）..." "info"
  new_users=$(awk -F: '$3 >= 1000 && $3 != 65534' /etc/passwd)
  if [ -n "$new_users" ]; then
    echo_check "User Info" "发现新增用户:" "warning"
    echo "$new_users"
  else
    echo_check "User Info" "未发现新增用户。" "info"
  fi

  echo_check "User Info" "[+] 检查是否存在新增用户组（GID >= 1000）..." "info"
  new_groups=$(awk -F: '$3 >= 1000' /etc/group)
  if [ -n "$new_groups" ]; then
    echo_check "User Info" "发现新增用户组:" "warning"
    echo "$new_groups"
  else
    echo_check "User Info" "未发现新增用户组。" "info"
  fi

}





# SSH后门检测
check_ssh_backdoor() {
  echo_check "SSH" "[+] 检查SSH后门..." "info"
  echo -e "================================"

  echo_check "SSH" "[+] 检查SSH配置文件中是否存在可疑命令..." "info"
  suspicious_commands=("wget" "curl" "bash -c" "sh -c" "base64" "python -c" "perl -e" "rm -rf")
  for cmd in "${suspicious_commands[@]}"; do
    if grep -qE "$cmd" /etc/ssh/sshd_config; then
      echo_check "SSH" "发现SSH配置文件中包含可疑命令: $cmd" "error"
      grep -E "$cmd" /etc/ssh/sshd_config
    fi
  done

  echo_check "SSH" "[+] 检查用户目录下的SSH后门..." "info"
  home_dirs=$(getent passwd | cut -d: -f6)
  for dir in $home_dirs; do
    authorized_keys_file="$dir/.ssh/authorized_keys"
    if [ -f "$authorized_keys_file" ]; then
      if grep -qE "command=.*\b(wget|curl|bash -c|sh -c|base64|python -c|perl -e)\b" "$authorized_keys_file"; then
        echo_check "SSH" "发现用户 $dir 的SSH公钥中包含可疑命令:" "error"
        grep -E "command=.*\b(wget|curl|bash -c|sh -c|base64|python -c|perl -e)\b" "$authorized_keys_file"
      fi
    fi
  done

  echo_check "SSH" "[+] 检查用户历史命令记录中是否存在SSH后门相关的命令..." "info"
  for user in $(cut -d: -f1 /etc/passwd); do
    history_file="/home/$user/.bash_history"
    if [ -f "$history_file" ]; then
      if grep -qE "\b(wget|curl|bash -c|sh -c|base64|python -c|perl -e)\b" "$history_file"; then
        echo_check "SSH" "用户 $user 的历史命令记录中发现可疑操作:" "warning"
        grep -E "\b(wget|curl|bash -c|sh -c|base64|python -c|perl -e)\b" "$history_file"
      fi
    fi
    history_file="/home/$user/.zsh_history"
    if [ -f "$history_file" ]; then
      if grep -qE "\b(wget|curl|bash -c|sh -c|base64|python -c|perl -e)\b" "$history_file"; then
        echo_check "SSH" "用户 $user 的历史命令记录中发现可疑操作:" "warning"
        grep -E "\b(wget|curl|bash -c|sh -c|base64|python -c|perl -e)\b" "$history_file"
      fi
    fi
  done

  echo_check "SSH" "[+] 检查全局历史命令记录..." "info"
  if [ -f "/root/.bash_history" ]; then
    if grep -qE "\b(wget|curl|bash -c|sh -c|base64|python -c|perl -e)\b" "/root/.bash_history"; then
      echo_check "SSH" "全局历史命令记录中发现可疑操作:" "warning"
      grep -E "\b(wget|curl|bash -c|sh -c|base64|python -c|perl -e)\b" "/root/.bash_history"
    fi
  fi
}


# 主审计函数
main_audit() {
  clean_cache_files                # 清理缓存文件
  fix_sensitive_file_permissions   # 修复敏感文件的权限，确保关键文件的访问权限符合安全要求。
  check_unknown_files              # 检查最近创建的文件

  collect_system_info              # 收集系统信息，获取系统的基本配置和状态信息，为后续检查提供基础数据。
  check_file_integrity             # 检查文件完整性，验证关键文件未被篡改。
  check_system_integrity           # 检查系统完整性，验证系统文件和配置是否被篡改。
  check_kernel_parameters          # 检查内核参数，确保内核配置符合安全要求。

  find_config_files                # 查找配置文件，定位系统中的关键配置文件，以便后续检查。

  check_suspicious_processes       # 检查可疑进程，查找可能的恶意进程或异常运行的程序。
  check_systemd_service_status     # 检查systemd服务状态，确认系统服务是否正常运行。
  check_abnormal_service_file_permissions # 检查服务文件的异常权限，确保服务配置文件的安全性。
  check_suspicious_service_configurations # 检查可疑的服务配置，查找可能导致安全隐患的配置问题。
  check_recent_user_group_changes  # 检查最近的用户和组变更，确认是否有异常的用户或组操作。

  check_nfs                         # NFS服务检查，确保NFS服务的配置安全。

  check_ssh_service_status         # 检查SSH服务状态，确保SSH服务正常运行且配置安全，同时查验用户命令历史记录。
  check_login_audit                # 检查登录审计，验证登录日志的完整性和安全性。


  check_sensitive_file_permissions # 检查敏感文件权限，确保敏感文件的访问权限严格限制。
  check_suid_sgid_files            # 检查SUID/SGID文件，查找可能被恶意利用的特殊权限文件。

  check_php_config                 # 检查PHP配置，确保PHP服务的配置安全。
  check_webshells                  # 检查Webshell，查找可能的PHP,JSP木马文件。

  check_http_services              # 检查HTTP服务，确认Web服务的运行状态和安全性。
  check_firewall                   # 检查防火墙配置，确保防火墙规则正确且有效。


  check_database_services          # 检查数据库服务，确认数据库服务是否正常运行。
  check_database_ports             # 检查数据库端口，确保数据库端口未被非法占用或暴露。


  check_user_information           # 检查用户信息，确认用户账户的安全性。
  check_ssh_backdoor               # 检查SSH后门，确认SSH服务无安全隐患。

  check_system_services            # 检查系统服务，确认系统服务的运行状态和安全性。
  check_cron_jobs                  # 检查计划任务，确认计划任务的合法性和安全性。

  check_system_updates             # 检查系统更新，确认系统是否有未安装的安全补丁。
  check_user_group_permissions     # 检查用户和组，确认用户和组的配置是否合理。
  check_network_connections        # 检查网络连接，确认网络连接的合法性和安全性。
  check_log_file_permissions       # 检查日志文件权限，确保日志文件的访问权限严格限制。
  check_selinux_apparmor           # 检查SELinux和AppArmor配置，确认强制访问控制策略是否启用。
  check_system_boot_entries        # 检查系统启动项，确认启动项中无恶意程序或配置。
  check_system_time_synchronization # 检查系统时间同步，确保系统时间与外部时间源同步。

  echo_check "Main" "自查完成。完整日志请查看: $LOG_FILE" "info" # 输出完成提示信息，告知用户自查完成，并提供日志文件路径。
}

# 调用主审计函数
main_audit