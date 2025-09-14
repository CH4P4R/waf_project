#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SmartWAF Test Script - Interactive Version
Used to test OWASP Top 10 attacks
"""

import requests
import time
import random
from urllib.parse import quote
import sys

# Test hedefi
BASE_URL = "http://localhost:5000"

# Test payloads - OWASP Top 10
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
    """Perform a single attack test"""
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
    """Show main menu"""
    print("\n" + "="*60)
    print("🛡️  SMARTWAF TEST MENU")
    print("="*60)
    print("1️⃣  Select specific attack type")
    print("2️⃣  Random test (10-50 attacks)")
    print("3️⃣  Stress test (100+ attacks)")
    print("4️⃣  Test all OWASP Top 10")
    print("5️⃣  Custom payload test")
    print("6️⃣  Multiple tests from single attack (50 times)")
    print("0️⃣  Exit")
    print("="*60)

def show_attack_types():
    """Show attack types"""
    print("\n📋 Available Attack Types:")
    print("-" * 40)
    for i, attack_type in enumerate(TEST_PAYLOADS.keys(), 1):
        print(f"{i:2d}. {attack_type}")
    print("-" * 40)

def test_specific_attack():
    """Test specific attack type"""
    show_attack_types()
    try:
        choice = int(input("\n🎯 Which attack type do you want to test? (1-10): "))
        attack_types = list(TEST_PAYLOADS.keys())
        
        if 1 <= choice <= len(attack_types):
            attack_type = attack_types[choice - 1]
            print(f"\n🚨 {attack_type} Attack Tests Starting...")
            print("-" * 50)
            
            endpoint = ENDPOINT_MAP.get(attack_type, "/search")
            print(f"📍 Endpoint: {endpoint}")
            
            for payload in TEST_PAYLOADS[attack_type]:
                success = test_attack(attack_type, payload, endpoint)
                status = "✅" if success else "❌"
                print(f"{status} {payload[:50]}...")
                time.sleep(0.8)
            
            print(f"\n✅ {attack_type} tests completed!")
        else:
            print("❌ Invalid selection!")
    except ValueError:
        print("❌ Please enter a valid number!")

def test_random_attacks():
    """Random attack tests"""
    try:
        count = int(input("\n🎲 How many random tests do you want to run? (10-50): "))
        if count < 10 or count > 50:
            print("❌ Please enter a number between 10-50!")
            return
        
        print(f"\n🎲 {count} Random Attack Tests Starting...")
        print("-" * 50)
        
        for i in range(count):
            # Select random attack type
            attack_type = random.choice(list(TEST_PAYLOADS.keys()))
            # Select random payload
            payload = random.choice(TEST_PAYLOADS[attack_type])
            endpoint = ENDPOINT_MAP.get(attack_type, "/search")
            
            success = test_attack(attack_type, payload, endpoint)
            status = "✅" if success else "❌"
            print(f"{i+1:2d}. {status} {attack_type}: {payload[:30]}...")
            time.sleep(0.3)
        
        print(f"\n✅ {count} random tests completed!")
    except ValueError:
        print("❌ Please enter a valid number!")

def test_stress():
    """Stress test - many attacks"""
    try:
        count = int(input("\n💥 How many stress tests do you want to run? (100-500): "))
        if count < 100 or count > 500:
            print("❌ Please enter a number between 100-500!")
            return
        
        print(f"\n💥 {count} Stress Tests Starting...")
        print("⚠️  This process may take some time...")
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
                print(f"📊 {i+1}/{count} - Successful: {successful}, Failed: {failed}")
            
            time.sleep(0.1)  # Hızlı test
        
        print(f"\n✅ Stress test completed!")
        print(f"📊 Total: {count} | Successful: {successful} | Failed: {failed}")
        print(f"📈 Success rate: %{(successful/count)*100:.1f}")
    except ValueError:
        print("❌ Please enter a valid number!")

def test_all_attacks():
    """Test all OWASP Top 10 attacks"""
    print("\n🔥 ALL OWASP TOP 10 ATTACK TESTS")
    print("=" * 60)
    
    total_tests = 0
    successful_tests = 0
    
    for attack_type, payloads in TEST_PAYLOADS.items():
        print(f"\n🚨 {attack_type} Attack Tests")
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
    
    print(f"\n✅ ALL TESTS COMPLETED!")
    print(f"📊 Total: {total_tests} | Successful: {successful_tests} | Failed: {total_tests - successful_tests}")
    print(f"📈 Success rate: %{(successful_tests/total_tests)*100:.1f}")

def test_custom_payload():
    """Test custom payload"""
    print("\n🛠️  CUSTOM PAYLOAD TEST")
    print("-" * 40)
    
    show_attack_types()
    try:
        choice = int(input("\n🎯 Which attack type do you want to test? (1-10): "))
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
            print("❌ Invalid selection!")
    except ValueError:
        print("❌ Please enter a valid number!")

def test_multiple_same():
    """Multiple tests from same attack type"""
    show_attack_types()
    try:
        choice = int(input("\n🎯 Which attack type do you want to test multiple times? (1-10): "))
        attack_types = list(TEST_PAYLOADS.keys())
        
        if 1 <= choice <= len(attack_types):
            attack_type = attack_types[choice - 1]
            count = int(input(f"\n🔢 How many {attack_type} tests do you want to run? (10-100): "))
            
            if count < 10 or count > 100:
                print("❌ Please enter a number between 10-100!")
                return
            
            print(f"\n🚨 {attack_type} - {count} Tests Starting...")
            print("-" * 50)
            
            endpoint = ENDPOINT_MAP.get(attack_type, "/search")
            payloads = TEST_PAYLOADS[attack_type]
            successful = 0
            
            for i in range(count):
                # Select random payload (same type)
                payload = random.choice(payloads)
                success = test_attack(attack_type, payload, endpoint)
                status = "✅" if success else "❌"
                
                if success:
                    successful += 1
                
                print(f"{i+1:3d}. {status} {payload[:40]}...")
                time.sleep(0.2)
            
            print(f"\n✅ {attack_type} multiple tests completed!")
            print(f"📊 Total: {count} | Successful: {successful} | Success rate: %{(successful/count)*100:.1f}")
        else:
            print("❌ Invalid selection!")
    except ValueError:
        print("❌ Please enter a valid number!")

def main_menu():
    """Main menu loop"""
    while True:
        show_menu()
        try:
            choice = input("\n🎯 Make your selection (0-6): ").strip()
            
            if choice == "0":
                print("\n👋 SmartWAF Test Script terminating...")
                print("🛡️  Stay secure!")
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
                print("❌ Invalid selection! Please enter a number between 0-6.")
            
            input("\n⏸️  Press Enter to continue...")
            
        except KeyboardInterrupt:
            print("\n\n👋 Script terminated!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
            input("\n⏸️  Press Enter to continue...")

if __name__ == "__main__":
    try:
        # Check if SmartWAF is running
        print("🔍 Checking SmartWAF connection...")
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✅ SmartWAF active! Starting test menu...")
            main_menu()
        else:
            print("❌ SmartWAF is not accessible!")
            print("💡 Start the system first: python app.py")
    except requests.exceptions.ConnectionError:
        print("❌ SmartWAF is not running!")
        print("💡 Start the system first: python app.py")
        print("🌐 Address: http://localhost:5000")
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("💡 Try starting SmartWAF: python app.py")