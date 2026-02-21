#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
═══════════════════════════════════════════════════════════════════
    Data Migration Script - نقل البيانات من JSON إلى PostgreSQL
    - ينقل كل البيانات الموجودة من ملفات JSON إلى قاعدة البيانات
    - يحافظ على كل المعلومات والإحصائيات
═══════════════════════════════════════════════════════════════════
"""

import json
import os
from datetime import datetime
from database import db

def migrate_users():
    """نقل المستخدمين من users.json"""
    print("\n📦 بدء نقل المستخدمين...")
    
    if not os.path.exists('users.json'):
        print("⚠️ ملف users.json غير موجود")
        return
    
    with open('users.json', 'r', encoding='utf-8') as f:
        users = json.load(f)
    
    migrated = 0
    for user_id, user_data in users.items():
        try:
            existing_user = db.get_user(user_id)
            if not existing_user:
                db.create_user(
                    user_id=user_id,
                    username=None,
                    first_name=None,
                    last_name=None,
                    referred_by=user_data.get('referred_by')
                )
                
                db.set_points(user_id, user_data.get('points', 0))
                
                for referral in user_data.get('referrals', []):
                    ref_user_id = referral.get('user_id')
                    if ref_user_id and ref_user_id != user_id:
                        try:
                            db.add_referral(user_id, ref_user_id, points=0)
                        except:
                            pass
                
                migrated += 1
                print(f"  ✅ تم نقل المستخدم: {user_id}")
            else:
                print(f"  ⏭️ المستخدم موجود: {user_id}")
        except Exception as e:
            print(f"  ❌ خطأ في نقل {user_id}: {e}")
    
    print(f"\n✅ تم نقل {migrated} مستخدم")

def migrate_sessions():
    """نقل الجلسات من sessions.json"""
    print("\n📦 بدء نقل الجلسات...")
    
    if not os.path.exists('sessions.json'):
        print("⚠️ ملف sessions.json غير موجود")
        return
    
    with open('sessions.json', 'r', encoding='utf-8') as f:
        sessions = json.load(f)
    
    migrated = 0
    for user_id, session_data in sessions.items():
        try:
            existing_user = db.get_user(user_id)
            if not existing_user:
                db.create_user(user_id=user_id)
            
            existing_session = db.get_session(user_id)
            if not existing_session:
                db.create_session(user_id)
                
                visits = session_data.get('visits', 0)
                if visits > 0:
                    cursor = db.get_cursor()
                    cursor.execute("""
                        UPDATE sessions SET visits = %s WHERE user_id = %s
                    """, (visits, user_id))
                    cursor.close()
                
                migrated += 1
                print(f"  ✅ تم نقل الجلسة: {user_id}")
            else:
                print(f"  ⏭️ الجلسة موجودة: {user_id}")
        except Exception as e:
            print(f"  ❌ خطأ في نقل جلسة {user_id}: {e}")
    
    print(f"\n✅ تم نقل {migrated} جلسة")

def migrate_promo_codes():
    """نقل أكواد الترويج من promo_links.json"""
    print("\n📦 بدء نقل أكواد الترويج...")
    
    if not os.path.exists('promo_links.json'):
        print("⚠️ ملف promo_links.json غير موجود")
        return
    
    with open('promo_links.json', 'r', encoding='utf-8') as f:
        promo_links = json.load(f)
    
    migrated = 0
    for code, promo_data in promo_links.items():
        try:
            db.create_promo_code(
                code=code,
                points=promo_data.get('points', 0),
                max_uses=promo_data.get('max_uses'),
                created_by=promo_data.get('created_by')
            )
            
            cursor = db.get_cursor()
            cursor.execute("""
                UPDATE promo_codes SET usage_count = %s WHERE code = %s
            """, (promo_data.get('usage_count', 0), code))
            cursor.close()
            
            migrated += 1
            print(f"  ✅ تم نقل الكود: {code}")
        except Exception as e:
            print(f"  ⏭️ الكود موجود أو خطأ: {code}")
    
    print(f"\n✅ تم نقل {migrated} كود ترويجي")

def migrate_forced_channels():
    """نقل القنوات الإجبارية من forced_channels.json"""
    print("\n📦 بدء نقل القنوات الإجبارية...")
    
    if not os.path.exists('forced_channels.json'):
        print("⚠️ ملف forced_channels.json غير موجود")
        return
    
    with open('forced_channels.json', 'r', encoding='utf-8') as f:
        channels = json.load(f)
    
    migrated = 0
    for channel in channels:
        try:
            db.add_forced_channel(
                channel_id=channel.get('channel_id', ''),
                channel_username=channel.get('channel_username', ''),
                channel_name=channel.get('channel_name', 'قناة')
            )
            migrated += 1
            print(f"  ✅ تم نقل القناة: {channel.get('channel_name')}")
        except Exception as e:
            print(f"  ❌ خطأ في نقل القناة: {e}")
    
    print(f"\n✅ تم نقل {migrated} قناة")

def migrate_assistant_admins():
    """نقل الأدمن المساعدين من assistant_admins.json"""
    print("\n📦 بدء نقل الأدمن المساعدين...")
    
    if not os.path.exists('assistant_admins.json'):
        print("⚠️ ملف assistant_admins.json غير موجود")
        return
    
    with open('assistant_admins.json', 'r', encoding='utf-8') as f:
        admins = json.load(f)
    
    migrated = 0
    cursor = db.get_cursor()
    for user_id in admins.keys():
        try:
            cursor.execute("""
                INSERT INTO assistant_admins (user_id, added_at)
                VALUES (%s, %s)
                ON CONFLICT (user_id) DO NOTHING
            """, (user_id, datetime.now()))
            migrated += 1
            print(f"  ✅ تم نقل الأدمن: {user_id}")
        except Exception as e:
            print(f"  ❌ خطأ في نقل {user_id}: {e}")
    
    cursor.close()
    print(f"\n✅ تم نقل {migrated} أدمن مساعد")

def run_migration():
    """تشغيل كل عمليات النقل"""
    print("═══════════════════════════════════════════════════════════════════")
    print("        🚀 بدء نقل البيانات من JSON إلى PostgreSQL")
    print("═══════════════════════════════════════════════════════════════════")
    
    try:
        migrate_users()
        migrate_sessions()
        migrate_promo_codes()
        migrate_forced_channels()
        migrate_assistant_admins()
        
        print("\n═══════════════════════════════════════════════════════════════════")
        print("        ✅ تم نقل كل البيانات بنجاح!")
        print("═══════════════════════════════════════════════════════════════════")
        
        stats = db.get_bot_statistics()
        print(f"\n📊 إحصائيات قاعدة البيانات:")
        print(f"   👥 إجمالي المستخدمين: {stats['total_users']}")
        print(f"   💎 إجمالي النقاط: {stats['total_points']}")
        print(f"   🔗 إجمالي الإحالات: {stats['total_referrals']}")
        print(f"   👁️ إجمالي الزيارات: {stats['total_visits']}")
        
    except Exception as e:
        print(f"\n❌ خطأ في عملية النقل: {e}")
        raise

if __name__ == "__main__":
    run_migration()
