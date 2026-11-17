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

constexpr int Auth::MAX_LOGIN_ATTEMPTS;
constexpr int Auth::LOCKOUT_SECONDS;

static std::string currentTimestamp() {
    auto now    = std::chrono::system_clock::now();
    auto timeT  = std::chrono::system_clock::to_time_t(now);

    std::tm* tmPtr = std::localtime(&timeT);

    std::ostringstream oss;
    oss << std::put_time(tmPtr, "%Y-%m-%d_%H:%M:%S");
    return oss.str();
}

Auth::Auth(UserDatabase& db) : db_(db) {}

bool Auth::isLocked(const std::string& username, int& remainingSeconds) {
    auto it = lockoutUntil_.find(username);
    if (it == lockoutUntil_.end()) return false;

    auto now = std::chrono::steady_clock::now();
    if (now < it->second) {
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(it->second - now);
        remainingSeconds = static_cast<int>(diff.count()) + 1;
        return true;
    }

    // Lockout expired
    lockoutUntil_.erase(it);
    failedAttempts_[username] = 0;
    remainingSeconds = 0;
    return false;
}

// ---------------------------------------------------------------------------
//  Registration
// ---------------------------------------------------------------------------
bool Auth::registerUser() {
    std::cout << "\n========== REGISTER ==========\n";

    std::string username = InputValidator::readLine("  Username : ");
    if (InputValidator::isEOF()) return false;

    auto uResult = InputValidator::validateUsername(username);
    if (!uResult.first) {
        std::cout << "  [ERROR] " << uResult.second << '\n';
        return false;
    }

    username = InputValidator::normalize(username);

    if (db_.hasUser(username)) {
        std::cout << "  [ERROR] Username '" << username << "' is already taken.\n";
        return false;
    }

    std::string password = InputValidator::readPassword("  Password : ");
    if (InputValidator::isEOF()) return false;

    auto pResult = InputValidator::validatePassword(password);
    if (!pResult.first) {
        std::cout << "  [ERROR] " << pResult.second << '\n';
        return false;
    }

    std::string confirm = InputValidator::readPassword("  Confirm  : ");
    if (InputValidator::isEOF()) return false;

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
        std::string rawUsername = InputValidator::readLine("  Username : ");
        if (InputValidator::isEOF()) return false;

        std::string username = InputValidator::normalize(rawUsername);

        int remainingLock = 0;
        if (isLocked(username, remainingLock)) {
            std::cout << "  [LOCKED] Account '" << username
                      << "' is temporarily locked due to repeated failed attempts.\n"
                      << "           Please wait " << remainingLock
                      << " second(s) before trying again.\n";
            return false;
        }

        std::string password = InputValidator::readPassword("  Password : ");
        if (InputValidator::isEOF()) return false;

        User user;
        bool found = db_.findUser(username, user);
        bool verified = found && Hasher::verify(password, user.getSalt(), user.getPasswordHash());

        if (!verified) {
            failedAttempts_[username]++;
            int currentFailures = failedAttempts_[username];

            if (currentFailures >= MAX_LOGIN_ATTEMPTS) {
                lockoutUntil_[username] = std::chrono::steady_clock::now() +
                                          std::chrono::seconds(LOCKOUT_SECONDS);
                failedAttempts_[username] = 0;
                std::cout << "  [LOCKED] Maximum failed attempts reached for account '"
                          << username << "'.\n"
                          << "           Account locked for " << LOCKOUT_SECONDS
                          << " seconds. Returning to main menu.\n";
                return false;
            }

            int left = MAX_LOGIN_ATTEMPTS - currentFailures;
            std::cout << "  [FAIL] Invalid username or password.  ("
                      << left << " attempt(s) left)\n";
            continue;
        }

        // Successful authentication
        failedAttempts_[username] = 0;
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

    std::string normUser = InputValidator::normalize(username);
    User user;
    if (!db_.findUser(normUser, user)) {
        std::cout << "  [ERROR] User not found.\n";
        return false;
    }

    std::string current = InputValidator::readPassword("  Current password  : ");
    if (InputValidator::isEOF()) return false;

    if (!Hasher::verify(current, user.getSalt(), user.getPasswordHash())) {
        std::cout << "  [ERROR] Current password is incorrect.\n";
        return false;
    }

    std::string newPass = InputValidator::readPassword("  New password      : ");
    if (InputValidator::isEOF()) return false;

    auto result = InputValidator::validatePassword(newPass);
    if (!result.first) {
        std::cout << "  [ERROR] " << result.second << '\n';
        return false;
    }

    std::string confirm = InputValidator::readPassword("  Confirm new pass  : ");
    if (InputValidator::isEOF()) return false;

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
