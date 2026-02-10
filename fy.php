<?php
class HtmlTableToJson {
    private $headers = [];
    
    public function __construct() {
        $this->setDefaultHeaders();
    }
    
    /**
     * 设置默认请求头
     */
    private function setDefaultHeaders() {
        $this->headers = [
            'Host: chengqing.cc',
            'Proxy-Connection: keep-alive',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'Accept: */*',
            'X-Requested-With: XMLHttpRequest',
            'Referer: http://chengqing.cc/',
            'Accept-Encoding: gzip, deflate',
            'Accept-Language: zh-CN,zh;q=0.9',
        ];
    }
    
    /**
     * 设置 Cookie
     * @param string $cookie Cookie 字符串
     */
    public function setCookie($cookie) {
        $this->headers[] = 'Cookie: ' . $this->sanitizeCookie($cookie);
    }
    
    /**
     * 清洗 Cookie 数据
     * @param string $cookie Cookie字符串
     * @return string 清洗后的Cookie
     */
    private function sanitizeCookie($cookie) {
        if (!$cookie) return '';
        
        // 只允许字母、数字、下划线、等号、分号、百分号、点、短横线
        $cookie = preg_replace('/[^a-zA-Z0-9_=%\.;\-\s]/', '', $cookie);
        
        // 防止注入攻击
        $dangerousPatterns = [
            '/\b(?:union|select|insert|update|delete|drop|create|alter|script|javascript|onload|onerror)\b/i',
            '/<script.*?>.*?<\/script>/si',
            '/javascript:/i',
            '/data:/i',
            '/vbscript:/i',
        ];
        
        foreach ($dangerousPatterns as $pattern) {
            $cookie = preg_replace($pattern, '', $cookie);
        }
        
        return trim($cookie);
    }
    
    /**
     * 安全清洗用户输入
     * @param string $input 用户输入
     * @param bool $allowHtml 是否允许HTML
     * @return string 清洗后的安全字符串
     */
    public static function sanitizeInput($input, $allowHtml = false) {
        if (!is_string($input)) {
            return '';
        }
        
        // 去除首尾空格
        $input = trim($input);
        
        // 长度限制（最大100个字符）
        if (mb_strlen($input, 'UTF-8') > 100) {
            $input = mb_substr($input, 0, 100, 'UTF-8');
        }
        
        if (!$allowHtml) {
            // HTML实体编码，防止XSS攻击
            $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            
            // 移除可能危险的字符
            $dangerousChars = ['<', '>', '"', "'", '`', '\\', '/'];
            $input = str_replace($dangerousChars, '', $input);
        }
        
        // 过滤SQL注入关键字
        $sqlKeywords = [
            'union', 'select', 'insert', 'update', 'delete', 'drop', 
            'create', 'alter', 'truncate', 'execute', 'exec', '--', 
            '/*', '*/', 'sleep', 'benchmark', 'information_schema'
        ];
        
        foreach ($sqlKeywords as $keyword) {
            $pattern = '/\b' . preg_quote($keyword, '/') . '\b/i';
            $input = preg_replace($pattern, '', $input);
        }
        
        // 防止命令注入
        $commandInjectionPatterns = [
            '/\|\s*[a-z]/i',
            '/\&\s*[a-z]/i',
            '/\;\s*[a-z]/i',
            '/\$\s*\(/',
            '/\`.*\`/',
            '/\$(?:\w+|\{[^}]+\})/',
        ];
        
        foreach ($commandInjectionPatterns as $pattern) {
            $input = preg_replace($pattern, '', $input);
        }
        
        // 验证输入格式（允许中文、英文、数字、常用标点）
        if (!preg_match('/^[\x{4e00}-\x{9fa5}a-zA-Z0-9_\-\s，。！？、；："'."'".'（）《》【】·～—…@#\$%\^&\*\+=\[\]\{\}\|\\\\:;<>\.\/\!\?\~\`]+$/u', $input)) {
            // 如果不匹配，只保留安全字符
            $input = preg_replace('/[^\x{4e00}-\x{9fa5}a-zA-Z0-9_\-\s，。！？、；："'."'".'（）《》【】·～—…@#\$%\^&\*\+=\[\]\{\}\|\\\\:;<>\.\/\!\?\~\`]/u', '', $input);
        }
        
        return $input;
    }
    
    /**
     * 验证用户名
     * @param string $username 用户名
     * @return bool 是否有效
     */
    public static function validateUsername($username) {
        if (!is_string($username) || empty($username)) {
            return false;
        }
        
        // 长度检查
        $length = mb_strlen($username, 'UTF-8');
        if ($length < 2 || $length > 30) {
            return false;
        }
        
        // 允许中文、英文、数字、下划线
        return preg_match('/^[\x{4e00}-\x{9fa5}a-zA-Z0-9_]+$/u', $username) === 1;
    }
    
    /**
     * 验证页码
     * @param mixed $page 页码
     * @return int 有效的页码
     */
    public static function validatePage($page) {
        $page = intval($page);
        if ($page < 1) {
            $page = 1;
        }
        
        // 最大页码限制
        if ($page > 1000) {
            $page = 1000;
        }
        
        return $page;
    }
    
    /**
     * 发送 GET 请求
     * @param string $url 请求URL
     * @return string 响应内容
     */
    private function sendRequest($url) {
        // 验证URL格式
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new Exception('无效的URL格式');
        }
        
        // 只允许HTTP/HTTPS协议
        $parsedUrl = parse_url($url);
        if (!in_array($parsedUrl['scheme'] ?? '', ['http', 'https'])) {
            throw new Exception('只支持HTTP/HTTPS协议');
        }
        
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => 'gzip',
            CURLOPT_HTTPHEADER => $this->headers,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_TIMEOUT => 30, // 30秒超时
            CURLOPT_CONNECTTIMEOUT => 10, // 10秒连接超时
            CURLOPT_MAXREDIRS => 3, // 最大重定向次数
            CURLOPT_FOLLOWLOCATION => true, // 跟随重定向
        ]);
        
        $response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new Exception('请求失败: ' . $error);
        }
        
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            throw new Exception('HTTP错误: ' . $httpCode);
        }
        
        return $response;
    }
    
    /**
     * 解析 HTML 表格为数组
     * @param string $html HTML内容
     * @return array 解析后的数据
     */
    private function parseHtmlTable($html) {
        // 防止XXE攻击
        $dom = new DOMDocument();
        
        // 抑制HTML解析错误
        $internalErrors = libxml_use_internal_errors(true);
        
        @$dom->loadHTML('<?xml encoding="UTF-8">' . $html);
        
        libxml_clear_errors();
        libxml_use_internal_errors($internalErrors);
        
        $result = [];
        $rows = $dom->getElementsByTagName('tr');
        
        // 跳过表头行
        $isFirstRow = true;
        
        foreach ($rows as $row) {
            if ($isFirstRow) {
                $isFirstRow = false;
                continue;
            }
            
            $columns = $row->getElementsByTagName('td');
            $rowData = [];
            $colIndex = 0;
            
            foreach ($columns as $col) {
                // 提取链接和文本，并进行安全清洗
                $links = $col->getElementsByTagName('a');
                $text = self::sanitizeInput(trim($col->textContent));
                
                if ($links->length > 0) {
                    $link = $links->item(0)->getAttribute('href');
                    // 验证URL
                    $link = filter_var($link, FILTER_SANITIZE_URL);
                    if (!filter_var($link, FILTER_VALIDATE_URL)) {
                        $link = '';
                    }
                    
                    $rowData[] = [
                        'text' => $text,
                        'link' => $link
                    ];
                } else {
                    $rowData[] = $text;
                }
                
                $colIndex++;
            }
            
            if (!empty($rowData)) {
                $result[] = [
                    'tieba' => $rowData[0] ?? null,
                    'subject' => $rowData[1] ?? null,
                    'content' => $rowData[2] ?? null,
                    'time' => $rowData[3] ?? null
                ];
            }
        }
        
        return $result;
    }
    
    /**
     * 获取数据并转换为JSON
     * @param string $username 用户名
     * @param int $page 页码
     * @param string|null $cookie Cookie
     * @return string JSON格式数据
     */
    public function getDataAsJson($username, $page = 1, $cookie = null) {
        try {
            // 验证和清洗输入
            if (!self::validateUsername($username)) {
                return json_encode([
                    'status' => 'error',
                    'message' => '无效的用户名格式'
                ], JSON_UNESCAPED_UNICODE);
            }
            
            $page = self::validatePage($page);
            $username = self::sanitizeInput($username);
            
            // 设置Cookie（如果提供）
            if ($cookie) {
                $this->setCookie($cookie);
            }
            
            // 构建URL（用户名需要URL编码）
            $encodedUsername = urlencode($username);
            $url = "http://chengqing.cc/ajax_re.php?username={$encodedUsername}&pn={$page}";
            
            // 发送请求
            $html = $this->sendRequest($url);
            
            // 解析HTML表格
            $data = $this->parseHtmlTable($html);
            
            // 记录日志（可选）
            $this->logRequest($username, $page, count($data));
            
            // 返回JSON
            return json_encode([
                'status' => 'success',
                'data' => $data,
                'meta' => [
                    'username' => $username,
                    'page' => $page,
                    'count' => count($data),
                    'timestamp' => date('Y-m-d H:i:s')
                ]
            ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
            
        } catch (Exception $e) {
            // 安全地返回错误信息，不泄露敏感信息
            $errorMessage = '获取数据失败';
            if (strpos($e->getMessage(), 'HTTP错误') !== false) {
                $errorMessage = '远程服务器错误';
            }
            
            return json_encode([
                'status' => 'error',
                'message' => $errorMessage
            ], JSON_UNESCAPED_UNICODE);
        }
    }
    
    /**
     * 记录请求日志
     * @param string $username 用户名
     * @param int $page 页码
     * @param int $dataCount 数据数量
     */
    private function logRequest($username, $page, $dataCount) {
        $logDir = __DIR__ . '/logs';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        $logFile = $logDir . '/requests.log';
        $logData = sprintf(
            "[%s] IP: %s | Username: %s | Page: %d | Count: %d\n",
            date('Y-m-d H:i:s'),
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $username,
            $page,
            $dataCount
        );
        
        @file_put_contents($logFile, $logData, FILE_APPEND | LOCK_EX);
    }
}

// 安全配置
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// 处理用户请求
if (isset($_GET['msg'])) {
    $parser = new HtmlTableToJson();
    
    // 清洗用户输入
    $msg = HtmlTableToJson::sanitizeInput($_GET['msg']);
    $page = isset($_GET['page']) ? HtmlTableToJson::validatePage($_GET['page']) : 1;
    
    // 可选：设置Cookie（如果需要）
    // $cookie = 'your_cookie_here';
    // $parser->setCookie($cookie);
    
    header('Content-Type: application/json; charset=utf-8');
    
    // 添加CORS头（根据需求调整）
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET');
    
    // 设置缓存控制
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    echo $parser->getDataAsJson($msg, $page);
    exit;
}
