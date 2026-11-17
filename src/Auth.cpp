// ============================================================================
//  Auth.cpp — Registration, login, and password-change workflows
// ============================================================================

#include "Auth.h"
#include "Hasher.h"
#include "InputValidator.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

static std::string currentTimestamp() {
    auto now    = std::chrono::system_clock::now();
    auto timeT  = std::chrono::system_clock::to_time_t(now);

    std::tm* tmPtr = std::localtime(&timeT);

    std::ostringstream oss;
    oss << std::put_time(tmPtr, "%Y-%m-%d_%H:%M:%S");
    return oss.str();
}

Auth::Auth(UserDatabase& db) : db_(db) {}

// ---------------------------------------------------------------------------
//  Registration
// ---------------------------------------------------------------------------
bool Auth::registerUser() {
    std::cout << "\n========== REGISTER ==========\n";

    std::string username = InputValidator::readLine("  Username : ");
    auto uResult = InputValidator::validateUsername(username);
    if (!uResult.first) {
        std::cout << "  [ERROR] " << uResult.second << '\n';
        return false;
    }
    if (db_.hasUser(username)) {
        std::cout << "  [ERROR] Username '" << username << "' is already taken.\n";
        return false;
    }

    std::string password = InputValidator::readPassword("  Password : ");
    auto pResult = InputValidator::validatePassword(password);
    if (!pResult.first) {
        std::cout << "  [ERROR] " << pResult.second << '\n';
        return false;
    }

    std::string confirm = InputValidator::readPassword("  Confirm  : ");
    if (password != confirm) {
        std::cout << "  [ERROR] Passwords do not match.\n";
        return false;
    }

    std::string salt = Hasher::generateSalt();
    std::string hash = Hasher::hashPassword(password, salt);

    User newUser(username, hash, salt, currentTimestamp());

    if (!db_.addUser(newUser)) {
        std::cout << "  [ERROR] Failed to save user. Please try again.\n";
        return false;
    }

    std::cout << "  [OK] Registration successful! You may now log in.\n";
    return true;
}

// ---------------------------------------------------------------------------
//  Login
// ---------------------------------------------------------------------------
bool Auth::login(std::string& loggedInUser) {
    std::cout << "\n============ LOGIN ===========\n";

    for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; ++attempt) {
        std::string username = InputValidator::readLine("  Username : ");
        std::string password = InputValidator::readPassword("  Password : ");

        User user;
        if (!db_.findUser(username, user)) {
            std::cout << "  [FAIL] Invalid username or password.  ("
                      << (MAX_LOGIN_ATTEMPTS - attempt) << " attempt(s) left)\n";
            continue;
        }

        if (!Hasher::verify(password, user.getSalt(), user.getPasswordHash())) {
            std::cout << "  [FAIL] Invalid username or password.  ("
                      << (MAX_LOGIN_ATTEMPTS - attempt) << " attempt(s) left)\n";
            continue;
        }

        user.incrementLoginCount();
        db_.updateUser(user);

        std::cout << "  [OK] Login successful!\n";
        loggedInUser = username;
        return true;
    }

    std::cout << "  [LOCKED] Too many failed attempts. Returning to main menu.\n";
    return false;
}

// ---------------------------------------------------------------------------
//  Change password
// ---------------------------------------------------------------------------
bool Auth::changePassword(const std::string& username) {
    std::cout << "\n====== CHANGE PASSWORD =======\n";

    User user;
    if (!db_.findUser(username, user)) {
        std::cout << "  [ERROR] User not found.\n";
        return false;
    }

    std::string current = InputValidator::readPassword("  Current password  : ");
    if (!Hasher::verify(current, user.getSalt(), user.getPasswordHash())) {
        std::cout << "  [ERROR] Current password is incorrect.\n";
        return false;
    }

    std::string newPass = InputValidator::readPassword("  New password      : ");
    auto result = InputValidator::validatePassword(newPass);
    if (!result.first) {
        std::cout << "  [ERROR] " << result.second << '\n';
        return false;
    }

    std::string confirm = InputValidator::readPassword("  Confirm new pass  : ");
    if (newPass != confirm) {
        std::cout << "  [ERROR] Passwords do not match.\n";
        return false;
    }

    if (newPass == current) {
        std::cout << "  [ERROR] New password must differ from the current one.\n";
        return false;
    }

    std::string newSalt = Hasher::generateSalt();
    std::string newHash = Hasher::hashPassword(newPass, newSalt);

    user.setSalt(newSalt);
    user.setPasswordHash(newHash);

    if (!db_.updateUser(user)) {
        std::cout << "  [ERROR] Failed to save. Please try again.\n";
        return false;
    }

    std::cout << "  [OK] Password changed successfully.\n";
    return true;
}
