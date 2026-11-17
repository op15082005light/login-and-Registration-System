#pragma once
// ============================================================================
//  InputValidator.h — Username / password policy enforcement
// ============================================================================

#include <string>
#include <utility>   // pair

class InputValidator {
public:
    // Username rules:
    //   • 3–20 characters
    //   • Alphanumeric + underscore only
    //   • Must start with a letter
    static std::pair<bool, std::string> validateUsername(const std::string& username);

    // Password rules:
    //   • Minimum 8 characters
    //   • At least one uppercase letter
    //   • At least one lowercase letter
    //   • At least one digit
    //   • At least one special character
    static std::pair<bool, std::string> validatePassword(const std::string& password);

    // Read a line from stdin (trimmed)
    static std::string readLine(const std::string& prompt);

    // Read a password from stdin (masked with asterisks on Windows, hidden on POSIX)
    static std::string readPassword(const std::string& prompt);
};
