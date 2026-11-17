// ============================================================================
//  test_suite.cpp — Comprehensive Unit & Integration Tests for Login System
// ============================================================================

#include "Hasher.h"
#include "User.h"
#include "UserDatabase.h"
#include "InputValidator.h"
#include "Auth.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// Helper test macro
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "  [FAILED] " << msg << " (line " << __LINE__ << ")\n"; \
            failedTests++; \
            return; \
        } \
    } while (0)

static int totalTests = 0;
static int passedTests = 0;
static int failedTests = 0;

void runTest(const std::string& testName, void (*testFunc)()) {
    totalTests++;
    std::cout << "[RUNNING] " << testName << " ... ";
    int preFailed = failedTests;
    testFunc();
    if (failedTests == preFailed) {
        passedTests++;
        std::cout << "PASSED\n";
    }
}

// ---------------------------------------------------------------------------
// 1. Cryptographic Test: NIST SHA-256 standard vectors
// ---------------------------------------------------------------------------
void test_sha256_nist_vectors() {
    // Vector 1: Empty string
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string hEmpty = Hasher::hashPassword("", "");
    TEST_ASSERT(hEmpty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "SHA-256 empty string vector mismatch");

    // Vector 2: "abc"
    // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::string hAbc = Hasher::hashPassword("abc", "");
    TEST_ASSERT(hAbc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "SHA-256 'abc' vector mismatch");

    // Vector 3: 56-byte message boundary test
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    std::string input56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    std::string h56 = Hasher::hashPassword(input56, "");
    TEST_ASSERT(h56 == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                "SHA-256 56-byte vector mismatch");
}

// ---------------------------------------------------------------------------
// 2. Salt Generation & Verification Test
// ---------------------------------------------------------------------------
void test_salt_and_verification() {
    std::string salt1 = Hasher::generateSalt();
    std::string salt2 = Hasher::generateSalt();

    TEST_ASSERT(salt1.length() == 32, "Salt length should be 32 hex chars (16 bytes)");
    TEST_ASSERT(salt2.length() == 32, "Salt length should be 32 hex chars (16 bytes)");
    TEST_ASSERT(salt1 != salt2, "Two randomly generated salts must not collide");

    std::string password = "MySecurePassword#99";
    std::string hash = Hasher::hashPassword(password, salt1);

    TEST_ASSERT(Hasher::verify(password, salt1, hash), "Password verification failed on correct password");
    TEST_ASSERT(!Hasher::verify("WrongPassword#99", salt1, hash), "Password verification passed on incorrect password");
    TEST_ASSERT(!Hasher::verify(password, salt2, hash), "Password verification passed with wrong salt");
}

// ---------------------------------------------------------------------------
// 3. Input Validation: Username Rules
// ---------------------------------------------------------------------------
void test_username_validation() {
    // Valid usernames
    TEST_ASSERT(InputValidator::validateUsername("alice").first, "Valid username 'alice' rejected");
    TEST_ASSERT(InputValidator::validateUsername("user_123").first, "Valid username 'user_123' rejected");
    TEST_ASSERT(InputValidator::validateUsername("dev_admin_2026").first, "Valid username 'dev_admin_2026' rejected");

    // Too short (< 3 chars)
    TEST_ASSERT(!InputValidator::validateUsername("ab").first, "Short username 'ab' accepted");
    TEST_ASSERT(!InputValidator::validateUsername("").first, "Empty username accepted");

    // Too long (> 20 chars)
    TEST_ASSERT(!InputValidator::validateUsername("this_username_is_way_too_long_for_policy").first, "Long username accepted");

    // Must start with letter
    TEST_ASSERT(!InputValidator::validateUsername("1user").first, "Username starting with number accepted");
    TEST_ASSERT(!InputValidator::validateUsername("_admin").first, "Username starting with underscore accepted");

    // Disallowed characters
    TEST_ASSERT(!InputValidator::validateUsername("user@name").first, "Username with '@' accepted");
    TEST_ASSERT(!InputValidator::validateUsername("user name").first, "Username with space accepted");
    TEST_ASSERT(!InputValidator::validateUsername("user-name").first, "Username with '-' accepted");
}

// ---------------------------------------------------------------------------
// 4. Input Validation: Password Rules
// ---------------------------------------------------------------------------
void test_password_validation() {
    // Valid password (>=8 chars, upper, lower, digit, special)
    TEST_ASSERT(InputValidator::validatePassword("Password#1").first, "Valid password 'Password#1' rejected");
    TEST_ASSERT(InputValidator::validatePassword("S3cur3!P@ss").first, "Valid password 'S3cur3!P@ss' rejected");

    // Too short (< 8 chars)
    TEST_ASSERT(!InputValidator::validatePassword("Pass#1").first, "Short password accepted");

    // Missing uppercase
    TEST_ASSERT(!InputValidator::validatePassword("password#1").first, "Password without uppercase accepted");

    // Missing lowercase
    TEST_ASSERT(!InputValidator::validatePassword("PASSWORD#1").first, "Password without lowercase accepted");

    // Missing digit
    TEST_ASSERT(!InputValidator::validatePassword("Password#X").first, "Password without digit accepted");

    // Missing special character
    TEST_ASSERT(!InputValidator::validatePassword("Password123").first, "Password without special char accepted");
}

// ---------------------------------------------------------------------------
// 5. User Serialization & Deserialization
// ---------------------------------------------------------------------------
void test_user_serialization() {
    User u1("john_doe", "fakehash123", "fakesalt456", "2026-11-17_08:00:00");
    u1.incrementLoginCount();
    u1.incrementLoginCount();

    std::string serialized = u1.serialize();
    TEST_ASSERT(serialized == "john_doe|fakehash123|fakesalt456|2026-11-17_08:00:00|2",
                "Serialized user record mismatch");

    User u2 = User::deserialize(serialized);
    TEST_ASSERT(u2.getUsername() == "john_doe", "Deserialized username mismatch");
    TEST_ASSERT(u2.getPasswordHash() == "fakehash123", "Deserialized hash mismatch");
    TEST_ASSERT(u2.getSalt() == "fakesalt456", "Deserialized salt mismatch");
    TEST_ASSERT(u2.getCreatedAt() == "2026-11-17_08:00:00", "Deserialized timestamp mismatch");
    TEST_ASSERT(u2.getLoginCount() == 2, "Deserialized login count mismatch");

    // Corrupted record must throw std::runtime_error
    bool threw = false;
    try {
        User::deserialize("corrupted|record|only|four");
    } catch (const std::exception&) {
        threw = true;
    }
    TEST_ASSERT(threw, "Deserializing corrupted line did not throw exception");
}

// ---------------------------------------------------------------------------
// 6. UserDatabase Persistence & Recovery
// ---------------------------------------------------------------------------
void test_database_persistence() {
    const std::string testDbFile = "data/test_users.dat";
    std::remove(testDbFile.c_str());

    {
        UserDatabase db(testDbFile);
        TEST_ASSERT(db.load(), "Loading from non-existent file should succeed as empty DB");
        TEST_ASSERT(db.userCount() == 0, "Initial DB should be empty");

        User u1("charlie", "hash_c", "salt_c", "2026-11-17_08:10:00");
        TEST_ASSERT(db.addUser(u1), "Adding user charlie failed");
        TEST_ASSERT(db.hasUser("charlie"), "hasUser returned false for charlie");
        TEST_ASSERT(!db.addUser(u1), "Duplicate user addition should be rejected");

        User u2("diana", "hash_d", "salt_d", "2026-11-17_08:11:00");
        TEST_ASSERT(db.addUser(u2), "Adding user diana failed");
        TEST_ASSERT(db.userCount() == 2, "DB userCount should be 2");

        // Update user
        u1.setPasswordHash("new_hash_c");
        u1.incrementLoginCount();
        TEST_ASSERT(db.updateUser(u1), "Updating user charlie failed");
    }

    // Verify persistence by loading into a fresh DB instance
    {
        UserDatabase dbReloaded(testDbFile);
        TEST_ASSERT(dbReloaded.load(), "Reloading DB from disk failed");
        TEST_ASSERT(dbReloaded.userCount() == 2, "Reloaded DB should contain 2 users");

        User retrieved;
        TEST_ASSERT(dbReloaded.findUser("charlie", retrieved), "Finding charlie in reloaded DB failed");
        TEST_ASSERT(retrieved.getPasswordHash() == "new_hash_c", "Retrieved hash mismatch after reload");
        TEST_ASSERT(retrieved.getLoginCount() == 1, "Retrieved login count mismatch after reload");

        TEST_ASSERT(dbReloaded.findUser("diana", retrieved), "Finding diana in reloaded DB failed");
        TEST_ASSERT(!dbReloaded.findUser("non_existent", retrieved), "Non-existent user lookup should return false");
    }

    // Corrupted record resilience
    {
        // Append a corrupted line to the file
        std::ofstream file(testDbFile, std::ios::app);
        file << "corrupt_line_without_pipes\n";
        file.close();

        UserDatabase dbResilient(testDbFile);
        TEST_ASSERT(dbResilient.load(), "DB load should gracefully skip corrupted record without crashing");
        TEST_ASSERT(dbResilient.userCount() == 2, "Valid records should still be loaded successfully");
    }

    std::remove(testDbFile.c_str());
}

// ---------------------------------------------------------------------------
// 7. Security: Plaintext Check
// ---------------------------------------------------------------------------
void test_no_plaintext_passwords() {
    const std::string testDbFile = "data/test_sec.dat";
    std::remove(testDbFile.c_str());

    std::string secretPassword = "SuperSecretPlainText#999";
    std::string salt = Hasher::generateSalt();
    std::string hash = Hasher::hashPassword(secretPassword, salt);

    {
        UserDatabase db(testDbFile);
        User u("sec_user", hash, salt, "2026-11-17_08:20:00");
        db.addUser(u);
    }

    // Read the physical file bytes
    std::ifstream file(testDbFile);
    std::string fileContent((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    file.close();

    // Verify plaintext password NEVER appears anywhere in the file
    TEST_ASSERT(fileContent.find(secretPassword) == std::string::npos,
                "SECURITY VULNERABILITY: Plaintext password found in saved database file!");
    TEST_ASSERT(fileContent.find(hash) != std::string::npos,
                "Hashed password should be present in file");

    std::remove(testDbFile.c_str());
}

int main() {
    std::cout << "========================================================\n";
    std::cout << "         LOGIN SYSTEM COMPREHENSIVE TEST SUITE         \n";
    std::cout << "========================================================\n\n";

    runTest("1. NIST SHA-256 Vector Verification", test_sha256_nist_vectors);
    runTest("2. Salt Randomness & Password Verification", test_salt_and_verification);
    runTest("3. Input Validator - Username Policy", test_username_validation);
    runTest("4. Input Validator - Password Policy", test_password_validation);
    runTest("5. User Serialization & Deserialization", test_user_serialization);
    runTest("6. UserDatabase Persistence & Recovery", test_database_persistence);
    runTest("7. Security Verification - No Plaintext Storage", test_no_plaintext_passwords);

    std::cout << "\n========================================================\n";
    std::cout << " Test Summary: " << passedTests << " / " << totalTests << " passed";
    if (failedTests > 0) {
        std::cout << " (" << failedTests << " failed)\n";
    } else {
        std::cout << " (ALL TESTS PASSED!)\n";
    }
    std::cout << "========================================================\n";

    return (failedTests == 0) ? 0 : 1;
}
