<?php
/**
 * AWD WAF - Web Application Firewall (含 IP 白名单/黑名单防火墙)
 * 用途: 三层拦截 →  IP 防火墙 (白名单优先 deny) → 10 类攻击特征检测 → 自动封禁
 * 部署: 通过 auto_prepend_file 自动加载, 或在入口文件 require
 *
 * ====== IP 防火墙 (推荐默认开启, 三层防御) ======
 * 层1: iptables (系统级, 流量完全丢弃)   → python3 defense/ip_firewall.py apply iptables
 * 层2: .htaccess / nginx (Web服务器级)    → python3 defense/ip_firewall.py generate htaccess --out .htaccess
 * 层3: 本 WAF.php (应用级, 直接 403)      → 部署在入口即可
 *
 * IP 规则来源优先级:
 *   1. 外部文件: /tmp/awd_ipfw/ip_firewall.php (由 ip_firewall.py generate waf 生成)
 *   2. 环境变量 AWD_WAF_WHITELIST_IP / AWD_WAF_BLACKLIST_IP (逗号分隔)
 *   3. 默认: 仅 127.0.0.1 白名单, 其余全部 deny
 *
 * 配置项:
 *   - AWD_WAF_MODE: 'block' (拦截) | 'log' (仅记录) | 'off' (关闭)
 *   - AWD_WAF_LOG:  攻击日志路径, 默认 /tmp/awd_waf.log
 *   - AWD_IPFW_DIR: IP 规则目录, 默认 /tmp/awd_ipfw
 *   - AWD_WAF_DEFAULT_POLICY: 'deny'(白名单默认拦截) | 'allow'(黑名单模式)
 *   - AWD_WAF_WHITELIST_IP: 环境变量注入白名单 (逗号分隔)
 *   - AWD_WAF_BLACKLIST_IP: 环境变量注入黑名单
 *   - AWD_WAF_AUTOBAN: 1=命中后自动调用 iptables 立刻拉黑 (默认 1)
 */

// 防止重复加载
if (defined('AWD_WAF_LOADED')) return;
define('AWD_WAF_LOADED', true);

class AWD_WAF {
    private static $instance = null;
    private $mode = 'block';
    private $logFile = '/tmp/awd_waf.log';
    private $banLogFile = '/tmp/awd_ipfw/ban.log';
    private $ipfwStateDir = '/tmp/awd_ipfw/state';
    private $whitelistIP = [];   // 字符串列表 (IP 或 CIDR)
    private $blacklistIP = [];
    private $defaultPolicy = 'deny'; // deny=白名单模式(默认)
    private $autoBan = true;
    private $banCooldown = 1800;
    private $blockedCount = 0;
    private $lastHitRule = '';
    private $ipBlocked = false;
    private $rules = [];
    private $request_data = [];

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->mode = getenv('AWD_WAF_MODE') ?: (defined('AWD_WAF_MODE') ? AWD_WAF_MODE : 'block');
        $this->logFile = getenv('AWD_WAF_LOG') ?: '/tmp/awd_waf.log';
        $ipfwDir = rtrim(getenv('AWD_IPFW_DIR') ?: (defined('AWD_IPFW_DIR') ? AWD_IPFW_DIR : '/tmp/awd_ipfw'), '/');
        $this->banLogFile = $ipfwDir . '/ban.log';
        $this->ipfwStateDir = $ipfwDir . '/state';
        @mkdir($ipfwDir, 0755, true);
        @mkdir($this->ipfwStateDir, 0755, true);

        $this->autoBan = (getenv('AWD_WAF_AUTOBAN') === false || getenv('AWD_WAF_AUTOBAN') === '1'
                          || (defined('AWD_WAF_AUTOBAN') && AWD_WAF_AUTOBAN));
        $this->defaultPolicy = (getenv('AWD_WAF_DEFAULT_POLICY')
                                ?: (defined('AWD_WAF_DEFAULT_POLICY') ? AWD_WAF_DEFAULT_POLICY : 'deny'));

        // ========= IP 规则加载: 优先级 1) 外部 ip_firewall.php =========
        $extFile = $ipfwDir . '/ip_firewall.php';
        if (file_exists($extFile)) {
            $GLOBALS['AWD_IPFW_WHITELIST'] = [];
            $GLOBALS['AWD_IPFW_BLACKLIST'] = [];
            @include_once $extFile;
            if (!empty($GLOBALS['AWD_IPFW_WHITELIST']) && is_array($GLOBALS['AWD_IPFW_WHITELIST'])) {
                $this->whitelistIP = array_merge($this->whitelistIP, $GLOBALS['AWD_IPFW_WHITELIST']);
            }
            if (!empty($GLOBALS['AWD_IPFW_BLACKLIST']) && is_array($GLOBALS['AWD_IPFW_BLACKLIST'])) {
                $this->blacklistIP = array_merge($this->blacklistIP, $GLOBALS['AWD_IPFW_BLACKLIST']);
            }
            if (defined('AWD_WAF_DEFAULT_POLICY_FROM_FILE') && AWD_WAF_DEFAULT_POLICY_FROM_FILE) {
                $this->defaultPolicy = AWD_WAF_DEFAULT_POLICY_FROM_FILE;
            }
        }

        // ========= 优先级 2) 环境变量 AWD_WAF_WHITELIST_IP =========
        $wl = getenv('AWD_WAF_WHITELIST_IP');
        if ($wl) {
            $this->whitelistIP = array_merge($this->whitelistIP, array_map('trim', explode(',', $wl)));
        }
        $bl = getenv('AWD_WAF_BLACKLIST_IP');
        if ($bl) {
            $this->blacklistIP = array_merge($this->blacklistIP, array_map('trim', explode(',', $bl)));
        }

        // ========= 优先级 3) 兜底默认: 回环地址白名单 =========
        if (empty($this->whitelistIP)) {
            $this->whitelistIP = ['127.0.0.1', '::1'];
        }

        // 初始化 WAF 攻击特征规则
        $this->initRules();

        // 收集请求数据
        $this->collectRequestData();
    }

    /**
     * 初始化攻击检测规则
     */
    private function initRules() {
        $this->rules = [
            // ========= 1. SQL 注入检测 =========
            'sql_injection' => [
                'severity' => 'critical',
                'patterns' => [
                    // 联合查询
                    '/\bunion\b.*\bselect\b/i',
                    '/\bunion\b.*\bfrom\b/i',
                    '/union\s+select\s+/',
                    // 布尔盲注
                    "/('|\")\s*(or|and)\s*('|\")?\s*\d+\s*=\s*\d+/i",
                    "/('|\")\s*(or|and)\s*('|\")?\s*\w+\s*=\s*\w+/i",
                    '/\bor\s+1\s*=\s*1\b/i',
                    '/\band\s+1\s*=\s*1\b/i',
                    '/\bor\s+\'1\'\s*=\s*\'1/i',
                    // 时间盲注
                    '/\bsleep\s*\(\s*\d+\s*\)/i',
                    '/\bbenchmark\s*\(/i',
                    '/\bwaitfor\s+delay\b/i',
                    '/if\s*\(\s*\d+\s*=\s*\d+\s*,\s*sleep/i',
                    // 报错注入
                    '/\bextractvalue\s*\(/i',
                    '/\bupdatexml\s*\(/i',
                    '/\bfloor\s*\(\s*rand/i',
                    '/convert\s*\(\s*int/i',
                    // 注释符
                    '/--\s*$/',
                    '/\/\*.*\*\//',
                    '/#$/',
                    // 信息架构
                    '/\binformation_schema\b/i',
                    '/\bmysql\.user\b/i',
                    // 堆叠查询
                    '/;\s*(drop|insert|update|delete|create)\s+/i',
                    '/;\s*(select|insert|update|delete)\s+/i',
                    // 编码绕过
                    '/0x[0-9a-f]{8,}/i',
                    '/char\s*\(\s*\d+\s*,/i',
                    '/concat\s*\(/i',
                    '/group_concat\s*\(/i',
                    // 文件读写
                    '/\bload_file\s*\(/i',
                    '/\binto\s+outfile\b/i',
                    '/\binto\s+dumpfile\b/i',
                ]
            ],

            // ========= 2. XSS 检测 =========
            'xss' => [
                'severity' => 'high',
                'patterns' => [
                    '/<script[^>]*>/i',
                    '/<\/script>/i',
                    '/javascript\s*:/i',
                    '/\bon\w+\s*=\s*["\']?[^"\']*\(/i',
                    '/\bon(error|load|click|mouseover|focus|submit|change)\s*=/i',
                    '/<img[^>]+onerror/i',
                    '/<svg[^>]+onload/i',
                    '/<body[^>]+onload/i',
                    '/<iframe[^>]*>/i',
                    '/<object[^>]*>/i',
                    '/<embed[^>]*>/i',
                    '/<svg[^>]*>/i',
                    '/eval\s*\(/i',
                    '/alert\s*\(/i',
                    '/prompt\s*\(/i',
                    '/confirm\s*\(/i',
                    '/document\.cookie/i',
                    '/document\.domain/i',
                    '/document\.write/i',
                    '/window\.location/i',
                    '/String\.fromCharCode/i',
                    '/<details[^>]+ontoggle/i',
                    '/<input[^>]+onfocus/i',
                    '/<form[^>]+onsubmit/i',
                ]
            ],

            // ========= 3. 命令执行检测 =========
            'command_injection' => [
                'severity' => 'critical',
                'patterns' => [
                    // 命令分隔符
                    '/;\s*(id|whoami|uname|ls|cat|wget|curl|bash|sh|nc|python)\b/i',
                    '/\|\s*(id|whoami|uname|ls|cat|wget|curl|bash|sh|nc|python)\b/i',
                    '/\|\|\s*(id|whoami|uname|ls|cat|wget|curl|bash|sh|nc|python)\b/i',
                    '/&&\s*(id|whoami|uname|ls|cat|wget|curl|bash|sh|nc|python)\b/i',
                    '/&\s*(id|whoami|uname|ls|cat|wget|curl|bash|sh|nc|python)\b/i',
                    // 反引号
                    '/`[^`]+`/',
                    // $()
                    '/\$\([^)]+\)/',
                    // 反弹 Shell
                    '/\/dev\/tcp\//i',
                    '/bash\s+-i/i',
                    '/sh\s+-i/i',
                    '/nc\s+-e/i',
                    '/python.*socket/i',
                    '/perl.*socket/i',
                    '/ruby.*socket/i',
                    // PHP 代码执行
                    '/\beval\s*\(/i',
                    '/\bassert\s*\(/i',
                    '/\bsystem\s*\(/i',
                    '/\bexec\s*\(/i',
                    '/\bshell_exec\s*\(/i',
                    '/\bpassthru\s*\(/i',
                    '/\bproc_open\s*\(/i',
                    '/\bpopen\s*\(/i',
                    '/\bcreate_function\s*\(/i',
                    '/preg_replace\s*\(\s*["\'].*\/e/i',
                    // 危险函数调用
                    '/\bsystem\s*\(\s*\$/i',
                    '/\bexec\s*\(\s*\$/i',
                    '/\beval\s*\(\s*\$/i',
                    // 命令拼接绕过
                    '/\$\{IFS\}/i',
                    '/\$[a-z]/i',
                    '/\b\/\?{3}\//i',
                ]
            ],

            // ========= 4. 文件包含检测 =========
            'file_inclusion' => [
                'severity' => 'critical',
                'patterns' => [
                    // PHP 协议
                    '/php:\/\/filter/i',
                    '/php:\/\/input/i',
                    '/php:\/\/stdin/i',
                    '/php:\/\/memory/i',
                    '/php:\/\/temp/i',
                    // 其他协议
                    '/file:\/\/\//i',
                    '/data:\/\/text/i',
                    '/data:\/\/image/i',
                    '/expect:\/\//i',
                    '/phar:\/\//i',
                    '/zip:\/\//i',
                    '/compress\.zlib:\/\//i',
                    '/compress\.bzip2:\/\//i',
                    '/glob:\/\//i',
                    // 路径遍历
                    '/\.\.\//',
                    '/\.\.\\\\/',
                    '/\.\.%2f/i',
                    '/\.\.%5c/i',
                    '/%2e%2e/i',
                    // 敏感文件
                    '/\/etc\/passwd/i',
                    '/\/etc\/shadow/i',
                    '/\/etc\/hosts/i',
                    '/\/proc\/self\//i',
                    '/\/proc\/version/i',
                    '/\/var\/log\//i',
                    '/\/var\/www\//i',
                    '/\/root\//i',
                    // 00 截断
                    '/%00/',
                    '/\x00/',
                ]
            ],

            // ========= 5. 文件上传检测 =========
            'file_upload' => [
                'severity' => 'critical',
                'patterns' => [
                    // 可执行扩展名
                    '/\.php\b/i',
                    '/\.phtml\b/i',
                    '/\.php3\b/i',
                    '/\.php4\b/i',
                    '/\.php5\b/i',
                    '/\.php7\b/i',
                    '/\.phps\b/i',
                    '/\.pht\b/i',
                    '/\.phar\b/i',
                    '/\.shtml\b/i',
                    '/\.htaccess\b/i',
                    '/\.user\.ini\b/i',
                    '/\.asp\b/i',
                    '/\.aspx\b/i',
                    '/\.jsp\b/i',
                    '/\.cer\b/i',
                    '/\.asa\b/i',
                    // 00 截断
                    '/\.php%00/i',
                    '/\.php\x00/i',
                    // 双写绕过
                    '/\.php\s/i',
                    '/\.php\./i',
                    '/\.php\.\./i',
                    // 文件内容检测
                    '/<\?php/i',
                    '/<\?=/i',
                    '/<script\s+language\s*=\s*["\']?php/i',
                    '/<%/i',
                ]
            ],

            // ========= 6. 反序列化检测 =========
            'deserialization' => [
                'severity' => 'critical',
                'patterns' => [
                    // PHP 序列化
                    '/O:\d+:/',
                    '/a:\d+:\{/',
                    '/s:\d+:/',
                    '/i:\d+;/',
                    '/b:[01];/',
                    '/N;/',
                    '/d:[\d.]+;/',
                    // Java 序列化
                    '/\xac\xed\x00\x05/',
                    // Python pickle
                    '/cpos\n/',
                    '/cpickle/',
                    // Fastjson
                    '/"@type"/i',
                    '/java\.lang\.AutoCloseable/i',
                    '/com\.alibaba\.fastjson/i',
                    // Shiro
                    '/rememberMe=/',
                    // 反序列化函数
                    '/\bunserialize\s*\(/i',
                    '/\bObjectInputStream/i',
                    '/\bpickle\.loads?\s*\(/i',
                    '/\bMarshal\.load/i',
                ]
            ],

            // ========= 7. 路径遍历检测 =========
            'path_traversal' => [
                'severity' => 'high',
                'patterns' => [
                    '/\.\.\//',
                    '/\.\.\\\\/',
                    '/\.\.%2f/i',
                    '/\.\.%5c/i',
                    '/%2e%2e%2f/i',
                    '/%2e%2e%5c/i',
                    '/\.\.%c0%af/i',
                    '/\.\.%c0%25af/i',
                    '/%c0%ae%c0%ae/i',
                    '/\.\.;/',
                ]
            ],

            // ========= 8. SSRF 检测 =========
            'ssrf' => [
                'severity' => 'high',
                'patterns' => [
                    '/127\.0\.0\.1/i',
                    '/localhost/i',
                    '/0\.0\.0\.0/i',
                    '/\[::1\]/i',
                    '/\[::\]/i',
                    '/169\.254\./i',
                    '/10\.\d+\.\d+\.\d+/i',
                    '/172\.(1[6-9]|2\d|3[01])\./i',
                    '/192\.168\./i',
                    '/file:\/\/\//i',
                    '/gopher:\/\/\//i',
                    '/dict:\/\//i',
                    '/ldap:\/\//i',
                    '/jar:\/\//i',
                    '/netdoc:\/\//i',
                    // 云元数据
                    '/169\.254\.169\.254/i',
                    '/metadata\.google\.internal/i',
                ]
            ],

            // ========= 9. 后台路径探测 =========
            'admin_scan' => [
                'severity' => 'medium',
                'patterns' => [
                    '/\/admin\b/i',
                    '/\/phpmyadmin\b/i',
                    '/\/wp-admin\b/i',
                    '/\/manager\b/i',
                    '/\/console\b/i',
                    '/\/\.env\b/i',
                    '/\/\.git\b/i',
                    '/\/\.svn\b/i',
                    '/\/backup\b/i',
                    '/\/\.htaccess\b/i',
                    '/\/phpinfo\b/i',
                ]
            ],

            // ========= 10. 扫描器特征 =========
            'scanner' => [
                'severity' => 'medium',
                'patterns' => [
                    '/sqlmap/i',
                    '/nikto/i',
                    '/nmap/i',
                    '/masscan/i',
                    '/dirbuster/i',
                    '/gobuster/i',
                    '/wpscan/i',
                    '/acunetix/i',
                    '/nessus/i',
                    '/burp/i',
                    '/hydra/i',
                    '/metasploit/i',
                ]
            ],
        ];
    }

    /**
     * 收集所有请求数据
     */
    private function collectRequestData() {
        $this->request_data = [
            'GET' => $_GET,
            'POST' => $_POST,
            'COOKIE' => $_COOKIE,
            'REQUEST' => $_REQUEST,
            'SERVER' => [
                'HTTP_USER_AGENT' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'HTTP_REFERER' => $_SERVER['HTTP_REFERER'] ?? '',
                'HTTP_X_FORWARDED_FOR' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
                'QUERY_STRING' => $_SERVER['QUERY_STRING'] ?? '',
                'REQUEST_URI' => $_SERVER['REQUEST_URI'] ?? '',
                'PATH_INFO' => $_SERVER['PATH_INFO'] ?? '',
            ],
            'FILES' => [],
        ];

        // 处理上传文件
        if (!empty($_FILES)) {
            foreach ($_FILES as $key => $file) {
                $this->request_data['FILES'][$key] = [
                    'name' => $file['name'] ?? '',
                    'type' => $file['type'] ?? '',
                    'tmp_name' => $file['tmp_name'] ?? '',
                    'size' => $file['size'] ?? 0,
                ];
            }
        }

        // 处理原始 POST 数据
        $rawInput = file_get_contents('php://input');
        if ($rawInput) {
            $this->request_data['RAW_INPUT'] = $rawInput;
        }
    }

    /**
     * 主检测入口 (IP 防火墙先于 WAF 特征检测执行)
     */
    public function check() {
        if ($this->mode === 'off') {
            return true;
        }

        // ====== Step 1: IP 防火墙 (先执行, 优先级最高) ======
        $ipDecision = $this->checkIPFirewall();
        if ($ipDecision === 'BLOCK') {
            $this->ipBlocked = true;
            if ($this->mode === 'block') {
                $ip = $this->getClientIP();
                // 非白名单自动调用 iptables 立刻拉黑 (冷却窗口 30 分钟)
                $reason = $this->defaultPolicy === 'deny' ? 'waf_ip_not_in_whitelist' : 'waf_ip_in_blacklist';
                $this->logBan($ip, $reason);
                if ($this->autoBan) {
                    $this->autoBanIP($ip, $reason);
                }
                $this->blockRequest($reason);
                return false;
            }
        }

        // 白名单 IP 直接放行, 不再跑特征检测 (避免误拦自己的攻击机)
        if ($ipDecision === 'WHITELIST_PASS') {
            return true;
        }

        // ====== Step 2: WAF 攻击特征检测 (仅对非白名单 IP 执行) ======
        foreach ($this->request_data as $source => $data) {
            if (empty($data)) continue;
            $this->checkData($data, $source);
        }

        if ($this->blockedCount > 0 && $this->mode === 'block') {
            $ip = $this->getClientIP();
            $this->logBan($ip, 'waf_rule_hit:' . ($this->lastHitRule ?? 'unknown'));
            if ($this->autoBan) {
                $this->autoBanIP($ip, 'waf_rule_hit');
            }
            $this->blockRequest('waf_rule_hit');
            return false;
        }

        return true;
    }

    /**
     * IP 防火墙决策
     * 返回: 'WHITELIST_PASS' | 'BLOCK' | 'RULE_CHECK_PASS'
     */
    private function checkIPFirewall() {
        $ip = $this->getClientIP();
        // 黑名单 → 不管策略, 一律拦截
        if ($this->ipInList($ip, $this->blacklistIP)) {
            return 'BLOCK';
        }
        // 白名单 → 直接放行
        if ($this->ipInList($ip, $this->whitelistIP)) {
            return 'WHITELIST_PASS';
        }
        // 都不在 → 看默认策略: deny=拦截(白名单模式), allow=放行
        return $this->defaultPolicy === 'deny' ? 'BLOCK' : 'RULE_CHECK_PASS';
    }

    /**
     * 判断 IP 是否在列表中 (支持单个 IP + CIDR)
     */
    private function ipInList($ip, array $list) {
        if (in_array($ip, $list, true)) {
            return true;
        }
        foreach ($list as $entry) {
            if (strpos($entry, '/') !== false) {
                if ($this->cidrMatch($ip, $entry)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * CIDR 匹配 (支持 IPv4 / IPv6)
     */
    private function cidrMatch($ip, $cidr) {
        [$net, $mask] = explode('/', $cidr, 2) + [1 => 32];
        $mask = (int)$mask;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            && filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            $netLong = ip2long($net);
            if ($mask === 0) return true;
            $maskLong = ~((1 << (32 - $mask)) - 1);
            return ($ipLong & $maskLong) === ($netLong & $maskLong);
        }
        if (class_exists('IPLib\\Factory')) {
            // 可选: 用第三方库处理 IPv6 CIDR
        }
        // 朴素 IPv6 / 备用方案: 前缀字符串匹配
        if (strpos($ip, ':') !== false && strpos($net, ':') !== false) {
            $bytes = (int)ceil($mask / 8);
            return substr(bin2hex(inet_pton($ip)), 0, $bytes * 2)
                === substr(bin2hex(inet_pton($net)), 0, $bytes * 2);
        }
        return false;
    }

    /**
     * 写封禁日志 (同 Python ip_firewall.py auto-ban)
     */
    private function logBan($ip, $reason) {
        $line = '[' . date('Y-m-d H:i:s') . "] BAN $ip  reason=$reason  policy={$this->defaultPolicy}" . PHP_EOL;
        @file_put_contents($this->banLogFile, $line, FILE_APPEND | LOCK_EX);
    }

    /**
     * 自动封禁 (非阻塞 exec, 单 IP 冷却窗口避免重复调用 iptables)
     */
    private function autoBanIP($ip, $reason) {
        $coolFile = $this->ipfwStateDir . '/ban_cool_' . str_replace(['.', ':'], '_', $ip);
        $now = time();
        if (file_exists($coolFile)) {
            $last = (int)@file_get_contents($coolFile);
            if ($now - $last < $this->banCooldown) {
                return;
            }
        }
        @file_put_contents($coolFile, (string)$now);

        // 用 iptables -I (插最前面) 立刻丢包; 失败继续执行不影响用户请求
        $safeIp = escapeshellarg($ip);
        $safeComment = escapeshellarg('awd:waf_ban:' . $reason);
        @exec("iptables -I INPUT -s $safeIp -j DROP -m comment --comment $safeComment >/dev/null 2>&1 &");
        // 同时写入黑名单持久化 (append)
        $stateFile = dirname($this->ipfwStateDir) . '/waf_blacklist_auto.txt';
        @file_put_contents(
            $stateFile,
            date('Y-m-d H:i:s') . "\t" . $ip . "\t" . $reason . PHP_EOL,
            FILE_APPEND | LOCK_EX
        );
    }

    /**
     * 检测数据中的攻击特征
     */
    private function checkData($data, $source) {
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                $this->checkData($value, $source . '.' . $key);
            }
        } elseif (is_string($data)) {
            // URL 解码检测 (绕过编码绕过)
            $decoded = urldecode($data);
            $doubleDecoded = urldecode($decoded);
            $base64Decoded = $this->tryBase64Decode($data);

            $variants = [$data, $decoded, $doubleDecoded];
            if ($base64Decoded) {
                $variants[] = $base64Decoded;
            }

            foreach ($this->rules as $ruleName => $rule) {
                foreach ($rule['patterns'] as $pattern) {
                    foreach ($variants as $variant) {
                        if (@preg_match($pattern, $variant)) {
                            $this->logAttack($ruleName, $source, $data, $pattern);
                            $this->blockedCount++;
                            $this->lastHitRule = $ruleName;
                            return;
                        }
                    }
                }
            }
        }
    }

    /**
     * 尝试 Base64 解码
     */
    private function tryBase64Decode($data) {
        if (strlen($data) < 8 || !preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $data)) {
            return false;
        }
        $decoded = base64_decode($data, true);
        return $decoded ?: false;
    }

    /**
     * 记录攻击日志
     */
    private function logAttack($ruleName, $source, $data, $pattern) {
        $logEntry = [
            'time' => date('Y-m-d H:i:s'),
            'ip' => $this->getClientIP(),
            'rule' => $ruleName,
            'severity' => $this->rules[$ruleName]['severity'],
            'source' => $source,
            'data' => mb_substr($data, 0, 500),
            'pattern' => $pattern,
            'url' => $_SERVER['REQUEST_URI'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? '',
        ];

        $logLine = json_encode($logEntry, JSON_UNESCAPED_UNICODE) . "\n";

        // 写入日志文件
        @file_put_contents($this->logFile, $logLine, FILE_APPEND | LOCK_EX);

        // 输出到错误日志 (便于调试)
        if ($this->rules[$ruleName]['severity'] === 'critical') {
            error_log("[AWD WAF] $ruleName from {$logEntry['ip']}: " . mb_substr($data, 0, 100));
        }
    }

    /**
     * 拦截请求
     * @param string $reason 'waf_ip_not_in_whitelist' | 'waf_ip_in_blacklist' | 'waf_rule_hit'
     */
    private function blockRequest($reason = 'waf_rule_hit') {
        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');
        // 不缓存 403
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');

        $ip = $this->getClientIP();
        $time = date('Y-m-d H:i:s');

        $reasonText = [
            'waf_ip_not_in_whitelist' => 'IP 不在白名单中 (默认 deny 策略)',
            'waf_ip_in_blacklist'     => 'IP 命中黑名单',
            'waf_rule_hit'            => '请求内容命中 WAF 攻击特征 (' . htmlspecialchars($this->lastHitRule) . ')',
        ][$reason] ?? htmlspecialchars($reason);

        $title = ($this->ipBlocked || strpos($reason, 'ip_') !== false) ? '403 IP Blocked (AWD IP Firewall)' : '403 Forbidden (AWD WAF)';

        echo "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
        echo "<title>" . htmlspecialchars($title) . "</title>";
        echo "<style>body{font-family:-apple-system,Arial,sans-serif;max-width:620px;margin:60px auto;padding:20px;line-height:1.6;background:#fff}h1{color:#d32f2f}.box{border:1px solid #ddd;padding:14px 20px;border-radius:8px;background:#fafafa}code{background:#eee;padding:2px 6px;border-radius:4px}</style>";
        echo "</head><body>";
        echo "<h1>" . htmlspecialchars($title) . "</h1>";
        echo "<div class='box'>";
        echo "<p><b>拦截原因:</b> " . $reasonText . "</p>";
        echo "<p><b>客户端 IP:</b> <code>" . htmlspecialchars($ip) . "</code></p>";
        echo "<p><b>时间:</b> " . htmlspecialchars($time) . "</p>";
        if ($this->defaultPolicy === 'deny') {
            echo "<p style='color:#555'>本靶机已开启白名单模式，默认策略 = deny。如需放行请联系管理员将该 IP 加入白名单。</p>";
        }
        echo "</div>";
        echo "<hr style='margin-top:30px'>";
        echo "<p style='color:#999;font-size:13px'>AWD IP Firewall × WAF · 三层防御（iptables · Web Server · Application）</p>";
        echo "</body></html>";

        // 终止执行
        exit;
    }

    /**
     * 获取客户端真实 IP (考虑 X-Forwarded-For/X-Real-IP, 取第一个可信 IP)
     */
    public function getClientIP() {
        $headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR',
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $val = $_SERVER[$header];
                if (strpos($val, ',') !== false) {
                    $parts = explode(',', $val);
                    $first = trim($parts[0]);
                    if (filter_var($first, FILTER_VALIDATE_IP)) {
                        return $first;
                    }
                }
                $val = trim($val);
                if (filter_var($val, FILTER_VALIDATE_IP)) {
                    return $val;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * 获取统计数据
     */
    public function getStats() {
        $stats = [
            'blocked_count' => $this->blockedCount,
            'mode' => $this->mode,
            'rules_count' => count($this->rules),
            'log_file' => $this->logFile,
        ];

        // 统计日志
        if (file_exists($this->logFile)) {
            $logs = file($this->logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $stats['total_attacks'] = count($logs);

            // 按类型统计
            $byType = [];
            foreach ($logs as $line) {
                $entry = json_decode($line, true);
                if ($entry) {
                    $type = $entry['rule'] ?? 'unknown';
                    $byType[$type] = ($byType[$type] ?? 0) + 1;
                }
            }
            $stats['by_type'] = $byType;
        }

        return $stats;
    }
}

// ========= 自动启动 WAF =========
$awd_waf = AWD_WAF::getInstance();
$awd_waf->check();

// ========= 辅助函数 (供业务代码调用) =========

/**
 * 获取 WAF 统计信息
 */
function awd_waf_stats() {
    return AWD_WAF::getInstance()->getStats();
}

/**
 * 手动检查某个字符串是否包含攻击
 */
function awd_waf_check_string($string) {
    $waf = AWD_WAF::getInstance();
    $reflection = new ReflectionClass($waf);
    $rulesProperty = $reflection->getProperty('rules');
    $rulesProperty->setAccessible(true);
    $rules = $rulesProperty->getValue($waf);

    $results = [];
    foreach ($rules as $ruleName => $rule) {
        foreach ($rule['patterns'] as $pattern) {
            if (@preg_match($pattern, $string)) {
                $results[] = [
                    'rule' => $ruleName,
                    'severity' => $rule['severity'],
                    'pattern' => $pattern,
                ];
            }
        }
    }
    return $results;
}

/**
 * 清空 WAF 日志
 */
function awd_waf_clear_log() {
    $waf = AWD_WAF::getInstance();
    $reflection = new ReflectionClass($waf);
    $logProperty = $reflection->getProperty('logFile');
    $logProperty->setAccessible(true);
    $logFile = $logProperty->getValue($waf);
    @file_put_contents($logFile, '');
    return true;
}
