#pragma once
// ============================================================================
//  Auth.h — Authentication controller (register, login, change password)
// ============================================================================

#include "UserDatabase.h"
#include <chrono>
#include <string>
#include <unordered_map>

class Auth {
public:
    explicit Auth(UserDatabase& db);

    // Returns true on successful registration
    bool registerUser();

    // Returns true on successful login and fills 'loggedInUser' with username
    bool login(std::string& loggedInUser);

    // Change password for the currently logged-in user
    bool changePassword(const std::string& username);

    // Maximum consecutive failed login attempts before lockout
    static constexpr int MAX_LOGIN_ATTEMPTS = 3;

    // Cooldown duration in seconds when locked out
    static constexpr int LOCKOUT_SECONDS = 30;

    // Query if an account is currently locked out
    bool isLocked(const std::string& username, int& remainingSeconds);

private:
    UserDatabase& db_;
    std::unordered_map<std::string, int> failedAttempts_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lockoutUntil_;
};
