<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');

// تعطيل عرض الأخطاء للأمان
error_reporting(0);
ini_set('display_errors', 0);

// ═══════════════════════════════════════════════════════════════════
// نظام الحماية - API Key Verification
// ═══════════════════════════════════════════════════════════════════

// API Key - ضع هنا المفتاح السري الخاص بك
// احفظه في ملف منفصل أو متغير بيئة للأمان الإضافي
define('API_SECRET_KEY', 'YOUR_SECRET_API_KEY_HERE');

// التحقق من وجود API Key في الـ Headers
$headers = getallheaders();
$api_key = isset($headers['X-API-Key']) ? $headers['X-API-Key'] : '';

if ($api_key !== API_SECRET_KEY) {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'error' => 'Access Denied'
    ]);
    exit;
}

// التحقق من أن الطلب POST فقط
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => 'Method Not Allowed'
    ]);
    exit;
}

// ═══════════════════════════════════════════════════════════════════
// إعدادات قاعدة البيانات - Database Configuration
// ═══════════════════════════════════════════════════════════════════

// استخدم localhost عند الرفع على InfinityFree
define('DB_HOST', 'localhost');
define('DB_NAME', 'YOUR_DB_NAME');
define('DB_USER', 'YOUR_DB_USER');
define('DB_PASS', 'YOUR_DB_PASS');

// الاتصال بقاعدة البيانات
try {
    $pdo = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Database connection failed'
    ]);
    exit;
}

// ═══════════════════════════════════════════════════════════════════
// قراءة البيانات المرسلة - Read Request Data
// ═══════════════════════════════════════════════════════════════════

$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (!isset($data['action'])) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => 'Action not specified'
    ]);
    exit;
}

$action = $data['action'];
$params = isset($data['params']) ? $data['params'] : [];

// ═══════════════════════════════════════════════════════════════════
// معالجة الطلبات - Handle Requests
// ═══════════════════════════════════════════════════════════════════

try {
    switch ($action) {
        
        // إنشاء الجداول
        case 'create_tables':
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS users (
                    user_id VARCHAR(50) PRIMARY KEY,
                    username VARCHAR(100),
                    first_name VARCHAR(200),
                    last_name VARCHAR(200),
                    points INT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    referred_by VARCHAR(50),
                    total_visits INT DEFAULT 0,
                    language_code VARCHAR(10),
                    is_bot TINYINT(1) DEFAULT 0,
                    is_premium TINYINT(1) DEFAULT 0,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ");
            
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS referrals (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    referrer_id VARCHAR(50),
                    referred_id VARCHAR(50),
                    points_earned INT DEFAULT 5,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_referral (referrer_id, referred_id),
                    FOREIGN KEY (referrer_id) REFERENCES users(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (referred_id) REFERENCES users(user_id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ");
            
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS sessions (
                    user_id VARCHAR(50) PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    visits INT DEFAULT 0,
                    last_visit TIMESTAMP NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ");
            
            echo json_encode(['success' => true, 'message' => 'Tables created']);
            break;
        
        // الحصول على مستخدم
        case 'get_user':
            $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
            $stmt->execute([$params['user_id']]);
            $user = $stmt->fetch();
            echo json_encode(['success' => true, 'data' => $user ?: null]);
            break;
        
        // إنشاء مستخدم
        case 'create_user':
            $stmt = $pdo->prepare("
                INSERT INTO users (user_id, username, first_name, last_name, points, 
                                 referred_by, language_code, is_bot, is_premium, created_at, updated_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                    username = VALUES(username),
                    first_name = VALUES(first_name),
                    last_name = VALUES(last_name),
                    language_code = VALUES(language_code),
                    is_premium = VALUES(is_premium),
                    updated_at = NOW(),
                    last_seen = NOW()
            ");
            
            $stmt->execute([
                $params['user_id'],
                $params['username'] ?? null,
                $params['first_name'] ?? null,
                $params['last_name'] ?? null,
                $params['points'] ?? 2,
                $params['referred_by'] ?? null,
                $params['language_code'] ?? null,
                $params['is_bot'] ?? 0,
                $params['is_premium'] ?? 0
            ]);
            
            $stmt = $pdo->prepare("SELECT * FROM users WHERE user_id = ?");
            $stmt->execute([$params['user_id']]);
            $user = $stmt->fetch();
            
            echo json_encode(['success' => true, 'data' => $user]);
            break;
        
        // تحديث مستخدم
        case 'update_user':
            $user_id = $params['user_id'];
            unset($params['user_id']);
            
            if (empty($params)) {
                echo json_encode(['success' => false, 'error' => 'No fields to update']);
                break;
            }
            
            $set_parts = [];
            $values = [];
            foreach ($params as $key => $value) {
                $set_parts[] = "$key = ?";
                $values[] = $value;
            }
            $values[] = $user_id;
            
            $sql = "UPDATE users SET " . implode(', ', $set_parts) . ", updated_at = NOW(), last_seen = NOW() WHERE user_id = ?";
            $stmt = $pdo->prepare($sql);
            $stmt->execute($values);
            
            echo json_encode(['success' => true]);
            break;
        
        // إضافة نقاط
        case 'add_points':
            $stmt = $pdo->prepare("UPDATE users SET points = points + ?, updated_at = NOW() WHERE user_id = ?");
            $stmt->execute([$params['points'], $params['user_id']]);
            echo json_encode(['success' => true]);
            break;
        
        // تعيين نقاط
        case 'set_points':
            $stmt = $pdo->prepare("UPDATE users SET points = ?, updated_at = NOW() WHERE user_id = ?");
            $stmt->execute([$params['points'], $params['user_id']]);
            echo json_encode(['success' => true]);
            break;
        
        // إضافة إحالة
        case 'add_referral':
            $stmt = $pdo->prepare("
                INSERT IGNORE INTO referrals (referrer_id, referred_id, points_earned)
                VALUES (?, ?, ?)
            ");
            $stmt->execute([
                $params['referrer_id'],
                $params['referred_id'],
                $params['points'] ?? 5
            ]);
            
            $stmt = $pdo->prepare("UPDATE users SET points = points + ?, updated_at = NOW() WHERE user_id = ?");
            $stmt->execute([$params['points'] ?? 5, $params['referrer_id']]);
            
            echo json_encode(['success' => true]);
            break;
        
        // الحصول على إحالات مستخدم
        case 'get_user_referrals':
            $stmt = $pdo->prepare("
                SELECT r.*, u.username, u.first_name, u.last_name
                FROM referrals r
                JOIN users u ON r.referred_id = u.user_id
                WHERE r.referrer_id = ?
                ORDER BY r.created_at DESC
            ");
            $stmt->execute([$params['user_id']]);
            $referrals = $stmt->fetchAll();
            echo json_encode(['success' => true, 'data' => $referrals]);
            break;
        
        // البحث عن مستخدمين
        case 'search_users':
            $search = '%' . $params['query'] . '%';
            $stmt = $pdo->prepare("
                SELECT * FROM users 
                WHERE username LIKE ? 
                   OR first_name LIKE ? 
                   OR last_name LIKE ?
                   OR user_id = ?
                LIMIT 50
            ");
            $stmt->execute([$search, $search, $search, $params['query']]);
            $users = $stmt->fetchAll();
            echo json_encode(['success' => true, 'data' => $users]);
            break;
        
        // الحصول على جميع المستخدمين
        case 'get_all_users':
            $stmt = $pdo->query("SELECT * FROM users ORDER BY created_at DESC");
            $users = $stmt->fetchAll();
            echo json_encode(['success' => true, 'data' => $users]);
            break;
        
        // لوحة المتصدرين
        case 'get_leaderboard':
            $limit = $params['limit'] ?? 10;
            $stmt = $pdo->prepare("
                SELECT u.*, COUNT(r.id) as referral_count
                FROM users u
                LEFT JOIN referrals r ON u.user_id = r.referrer_id
                GROUP BY u.user_id
                ORDER BY u.points DESC, referral_count DESC
                LIMIT ?
            ");
            $stmt->execute([$limit]);
            $users = $stmt->fetchAll();
            echo json_encode(['success' => true, 'data' => $users]);
            break;
        
        // إنشاء جلسة
        case 'create_session':
            $stmt = $pdo->prepare("
                INSERT INTO sessions (user_id, created_at, visits, last_visit)
                VALUES (?, NOW(), 0, NOW())
                ON DUPLICATE KEY UPDATE last_visit = NOW()
            ");
            $stmt->execute([$params['user_id']]);
            
            $stmt = $pdo->prepare("SELECT * FROM sessions WHERE user_id = ?");
            $stmt->execute([$params['user_id']]);
            $session = $stmt->fetch();
            
            echo json_encode(['success' => true, 'data' => $session]);
            break;
        
        // زيادة زيارات الجلسة
        case 'increment_session_visits':
            $stmt = $pdo->prepare("
                UPDATE sessions SET visits = visits + 1, last_visit = NOW()
                WHERE user_id = ?
            ");
            $stmt->execute([$params['user_id']]);
            echo json_encode(['success' => true]);
            break;
        
        // الحصول على جلسة
        case 'get_session':
            $stmt = $pdo->prepare("SELECT * FROM sessions WHERE user_id = ?");
            $stmt->execute([$params['user_id']]);
            $session = $stmt->fetch();
            echo json_encode(['success' => true, 'data' => $session ?: null]);
            break;
        
        default:
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => 'Unknown action'
            ]);
            break;
    }
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Database error'
    ]);
}
?>