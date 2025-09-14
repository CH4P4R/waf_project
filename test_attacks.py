#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SmartWAF Test Script - İnteraktif Versiyon
OWASP Top 10 saldırılarını test etmek için kullanılır
"""

import requests
import time
import random
from urllib.parse import quote
import sys

# Test hedefi
BASE_URL = "http://localhost:5000"

# Test payload'ları - OWASP Top 10
TEST_PAYLOADS = {
    "XSS": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ],
    
    "SQLi": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT null,null,null--"
    ],
    
    "RCE": [
        "; ls -la",
        "&& cat /etc/passwd",
        "| whoami"
    ],
    
    "LFI": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/shadow"
    ],
    
    "CSRF": [
        "<form action='http://evil.com' method='POST'>",
        "<img src='http://evil.com/steal-cookie'>",
        "<script>document.location='http://evil.com'</script>"
    ],
    
    "IDOR": [
        "user_id=123",
        "profile_id=456",
        "account_id=789"
    ],
    
    "Directory_Traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/shadow"
    ],
    
    "LDAP_Injection": [
        "*)(uid=*))(|(uid=*",
        "*)(|(password=*))",
        "*)(|(objectClass=*))"
    ],
    
    "Sensitive_Data": [
        "password=123456",
        "credit_card=4111111111111111",
        "ssn=123-45-6789"
    ],
    
    "Security_Misconfig": [
        "debug=true",
        "admin=1",
        "test_mode=on"
    ]
}

def test_attack(attack_type, payload, endpoint="/search"):
    """Tek bir saldırı testi yap"""
    try:
        if endpoint == "/search":
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                data={"search": payload},
                timeout=5
            )
        elif endpoint == "/login":
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                data={"username": payload, "password": "test"},
                timeout=5
            )
        elif endpoint == "/user/123/profile":
            response = requests.get(
                f"{BASE_URL}{endpoint}?{payload}",
                timeout=5
            )
        elif endpoint == "/traverse":
            response = requests.get(
                f"{BASE_URL}{endpoint}?path={quote(payload)}",
                timeout=5
            )
        elif endpoint == "/ldap":
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                data={"query": payload},
                timeout=5
            )
        else:
            response = requests.get(
                f"{BASE_URL}{endpoint}?q={quote(payload)}",
                timeout=5
            )
        
        return response.status_code == 200
    except Exception:
        return False

# Endpoint mapping
ENDPOINT_MAP = {
    "XSS": "/search",
    "SQLi": "/search", 
    "RCE": "/search",
    "LFI": "/file",
    "CSRF": "/csrf-test",
    "IDOR": "/user/123/profile",
    "Directory_Traversal": "/traverse",
    "LDAP_Injection": "/ldap",
    "Sensitive_Data": "/api",
    "Security_Misconfig": "/config"
}

def show_menu():
    """Ana menüyü göster"""
    print("\n" + "="*60)
    print("🛡️  SMARTWAF TEST MENÜSÜ")
    print("="*60)
    print("1️⃣  Spesifik saldırı türü seç")
    print("2️⃣  Rastgele test (10-50 saldırı)")
    print("3️⃣  Stress test (100+ saldırı)")
    print("4️⃣  Tüm OWASP Top 10 test et")
    print("5️⃣  Özel payload test et")
    print("6️⃣  Tek saldırıdan çoklu test (50 adet)")
    print("0️⃣  Çıkış")
    print("="*60)

def show_attack_types():
    """Saldırı türlerini göster"""
    print("\n📋 Mevcut Saldırı Türleri:")
    print("-" * 40)
    for i, attack_type in enumerate(TEST_PAYLOADS.keys(), 1):
        print(f"{i:2d}. {attack_type}")
    print("-" * 40)

def test_specific_attack():
    """Spesifik saldırı türü test et"""
    show_attack_types()
    try:
        choice = int(input("\n🎯 Hangi saldırı türünü test etmek istiyorsun? (1-10): "))
        attack_types = list(TEST_PAYLOADS.keys())
        
        if 1 <= choice <= len(attack_types):
            attack_type = attack_types[choice - 1]
            print(f"\n🚨 {attack_type} Saldırı Testleri Başlatılıyor...")
            print("-" * 50)
            
            endpoint = ENDPOINT_MAP.get(attack_type, "/search")
            print(f"📍 Endpoint: {endpoint}")
            
            for payload in TEST_PAYLOADS[attack_type]:
                success = test_attack(attack_type, payload, endpoint)
                status = "✅" if success else "❌"
                print(f"{status} {payload[:50]}...")
                time.sleep(0.8)
            
            print(f"\n✅ {attack_type} testleri tamamlandı!")
        else:
            print("❌ Geçersiz seçim!")
    except ValueError:
        print("❌ Lütfen geçerli bir sayı girin!")

def test_random_attacks():
    """Rastgele saldırı testleri"""
    try:
        count = int(input("\n🎲 Kaç adet rastgele test yapmak istiyorsun? (10-50): "))
        if count < 10 or count > 50:
            print("❌ Lütfen 10-50 arası bir sayı girin!")
            return
        
        print(f"\n🎲 {count} Adet Rastgele Saldırı Testi Başlatılıyor...")
        print("-" * 50)
        
        for i in range(count):
            # Rastgele saldırı türü seç
            attack_type = random.choice(list(TEST_PAYLOADS.keys()))
            # Rastgele payload seç
            payload = random.choice(TEST_PAYLOADS[attack_type])
            endpoint = ENDPOINT_MAP.get(attack_type, "/search")
            
            success = test_attack(attack_type, payload, endpoint)
            status = "✅" if success else "❌"
            print(f"{i+1:2d}. {status} {attack_type}: {payload[:30]}...")
            time.sleep(0.3)
        
        print(f"\n✅ {count} rastgele test tamamlandı!")
    except ValueError:
        print("❌ Lütfen geçerli bir sayı girin!")

def test_stress():
    """Stress test - çok sayıda saldırı"""
    try:
        count = int(input("\n💥 Kaç adet stress test yapmak istiyorsun? (100-500): "))
        if count < 100 or count > 500:
            print("❌ Lütfen 100-500 arası bir sayı girin!")
            return
        
        print(f"\n💥 {count} Adet Stress Test Başlatılıyor...")
        print("⚠️  Bu işlem zaman alabilir...")
        print("-" * 50)
        
        successful = 0
        failed = 0
        
        for i in range(count):
            attack_type = random.choice(list(TEST_PAYLOADS.keys()))
            payload = random.choice(TEST_PAYLOADS[attack_type])
            endpoint = ENDPOINT_MAP.get(attack_type, "/search")
            
            success = test_attack(attack_type, payload, endpoint)
            if success:
                successful += 1
            else:
                failed += 1
            
            if i % 10 == 0:  # Her 10 testte rapor
                print(f"📊 {i+1}/{count} - Başarılı: {successful}, Başarısız: {failed}")
            
            time.sleep(0.1)  # Hızlı test
        
        print(f"\n✅ Stress test tamamlandı!")
        print(f"📊 Toplam: {count} | Başarılı: {successful} | Başarısız: {failed}")
        print(f"📈 Başarı oranı: %{(successful/count)*100:.1f}")
    except ValueError:
        print("❌ Lütfen geçerli bir sayı girin!")

def test_all_attacks():
    """Tüm OWASP Top 10 saldırılarını test et"""
    print("\n🔥 TÜM OWASP TOP 10 SALDIRI TESTLERİ")
    print("=" * 60)
    
    total_tests = 0
    successful_tests = 0
    
    for attack_type, payloads in TEST_PAYLOADS.items():
        print(f"\n🚨 {attack_type} Saldırı Testleri")
        print("-" * 40)
        
        endpoint = ENDPOINT_MAP.get(attack_type, "/search")
        print(f"📍 Endpoint: {endpoint}")
        
        for payload in payloads:
            success = test_attack(attack_type, payload, endpoint)
            status = "✅" if success else "❌"
            print(f"{status} {payload[:50]}...")
            
            total_tests += 1
            if success:
                successful_tests += 1
            
            time.sleep(0.5)
    
    print(f"\n✅ TÜM TESTLER TAMAMLANDI!")
    print(f"📊 Toplam: {total_tests} | Başarılı: {successful_tests} | Başarısız: {total_tests - successful_tests}")
    print(f"📈 Başarı oranı: %{(successful_tests/total_tests)*100:.1f}")

def test_custom_payload():
    """Özel payload test et"""
    print("\n🛠️  ÖZEL PAYLOAD TESTİ")
    print("-" * 40)
    
    show_attack_types()
    try:
        choice = int(input("\n🎯 Hangi saldırı türü olarak test etmek istiyorsun? (1-10): "))
        attack_types = list(TEST_PAYLOADS.keys())
        
        if 1 <= choice <= len(attack_types):
            attack_type = attack_types[choice - 1]
            endpoint = ENDPOINT_MAP.get(attack_type, "/search")
            
            payload = input(f"\n💣 {attack_type} payload'unu gir: ").strip()
            if not payload:
                print("❌ Boş payload!")
                return
            
            print(f"\n🧪 Test ediliyor: {attack_type}")
            print(f"📍 Endpoint: {endpoint}")
            print(f"💣 Payload: {payload}")
            print("-" * 40)
            
            success = test_attack(attack_type, payload, endpoint)
            status = "✅ BAŞARILI" if success else "❌ BAŞARISIZ"
            print(f"{status}")
        else:
            print("❌ Geçersiz seçim!")
    except ValueError:
        print("❌ Lütfen geçerli bir sayı girin!")

def test_multiple_same():
    """Aynı saldırı türünden çoklu test"""
    show_attack_types()
    try:
        choice = int(input("\n🎯 Hangi saldırı türünden çoklu test yapmak istiyorsun? (1-10): "))
        attack_types = list(TEST_PAYLOADS.keys())
        
        if 1 <= choice <= len(attack_types):
            attack_type = attack_types[choice - 1]
            count = int(input(f"\n🔢 {attack_type} saldırısından kaç adet test yapmak istiyorsun? (10-100): "))
            
            if count < 10 or count > 100:
                print("❌ Lütfen 10-100 arası bir sayı girin!")
                return
            
            print(f"\n🚨 {attack_type} - {count} Adet Test Başlatılıyor...")
            print("-" * 50)
            
            endpoint = ENDPOINT_MAP.get(attack_type, "/search")
            payloads = TEST_PAYLOADS[attack_type]
            successful = 0
            
            for i in range(count):
                # Rastgele payload seç (aynı türden)
                payload = random.choice(payloads)
                success = test_attack(attack_type, payload, endpoint)
                status = "✅" if success else "❌"
                
                if success:
                    successful += 1
                
                print(f"{i+1:3d}. {status} {payload[:40]}...")
                time.sleep(0.2)
            
            print(f"\n✅ {attack_type} çoklu test tamamlandı!")
            print(f"📊 Toplam: {count} | Başarılı: {successful} | Başarı oranı: %{(successful/count)*100:.1f}")
        else:
            print("❌ Geçersiz seçim!")
    except ValueError:
        print("❌ Lütfen geçerli bir sayı girin!")

def main_menu():
    """Ana menü döngüsü"""
    while True:
        show_menu()
        try:
            choice = input("\n🎯 Seçiminizi yapın (0-6): ").strip()
            
            if choice == "0":
                print("\n👋 SmartWAF Test Script'i sonlandırılıyor...")
                print("🛡️  Güvenli kalın!")
                break
            elif choice == "1":
                test_specific_attack()
            elif choice == "2":
                test_random_attacks()
            elif choice == "3":
                test_stress()
            elif choice == "4":
                test_all_attacks()
            elif choice == "5":
                test_custom_payload()
            elif choice == "6":
                test_multiple_same()
            else:
                print("❌ Geçersiz seçim! Lütfen 0-6 arası bir sayı girin.")
            
            input("\n⏸️  Devam etmek için Enter'a basın...")
            
        except KeyboardInterrupt:
            print("\n\n👋 Script sonlandırıldı!")
            break
        except Exception as e:
            print(f"\n❌ Hata: {e}")
            input("\n⏸️  Devam etmek için Enter'a basın...")

if __name__ == "__main__":
    try:
        # SmartWAF'ın çalışıp çalışmadığını kontrol et
        print("🔍 SmartWAF bağlantısı kontrol ediliyor...")
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✅ SmartWAF aktif! Test menüsü başlatılıyor...")
            main_menu()
        else:
            print("❌ SmartWAF erişilebilir değil!")
            print("💡 Önce sistemi başlatın: python app.py")
    except requests.exceptions.ConnectionError:
        print("❌ SmartWAF çalışmıyor!")
        print("💡 Önce sistemi başlatın: python app.py")
        print("🌐 Adres: http://localhost:5000")
    except Exception as e:
        print(f"❌ Bağlantı hatası: {e}")
        print("💡 SmartWAF'ı başlatmayı deneyin: python app.py")