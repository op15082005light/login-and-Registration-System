#pragma once
// ============================================================================
//  Auth.h — Authentication controller (register, login, change password)
// ============================================================================

#include "UserDatabase.h"
#include <string>

class Auth {
public:
    explicit Auth(UserDatabase& db);

    // Returns true on successful registration
    bool registerUser();

    // Returns true on successful login and fills 'loggedInUser' with username
    bool login(std::string& loggedInUser);

    // Change password for the currently logged-in user
    bool changePassword(const std::string& username);

    // Maximum consecutive failed login attempts before lockout message
    static constexpr int MAX_LOGIN_ATTEMPTS = 3;

private:
    UserDatabase& db_;
};
