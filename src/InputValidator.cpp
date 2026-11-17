// ============================================================================
//  InputValidator.cpp — Policy checks + safe console I/O
// ============================================================================

#include "InputValidator.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

#ifdef _WIN32
#  include <conio.h>
#  include <windows.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

// ---------------------------------------------------------------------------
//  Username validation
// ---------------------------------------------------------------------------
std::pair<bool, std::string>
InputValidator::validateUsername(const std::string& username) {
    if (username.size() < 3)
        return {false, "Username must be at least 3 characters."};
    if (username.size() > 20)
        return {false, "Username must be at most 20 characters."};
    if (!std::isalpha(static_cast<unsigned char>(username[0])))
        return {false, "Username must start with a letter."};

    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
            return {false, "Username may only contain letters, digits, and underscores."};
    }
    return {true, ""};
}

// ---------------------------------------------------------------------------
//  Password validation
// ---------------------------------------------------------------------------
std::pair<bool, std::string>
InputValidator::validatePassword(const std::string& password) {
    if (password.size() < 8)
        return {false, "Password must be at least 8 characters."};

    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        if (std::isupper(static_cast<unsigned char>(c))) hasUpper  = true;
        else if (std::islower(static_cast<unsigned char>(c))) hasLower  = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit  = true;
        else                                                   hasSpecial = true;
    }

    if (!hasUpper)   return {false, "Password must contain at least one uppercase letter."};
    if (!hasLower)   return {false, "Password must contain at least one lowercase letter."};
    if (!hasDigit)   return {false, "Password must contain at least one digit."};
    if (!hasSpecial) return {false, "Password must contain at least one special character."};

    return {true, ""};
}

// ---------------------------------------------------------------------------
//  Helper: detect if stdin is a terminal (not a pipe)
// ---------------------------------------------------------------------------
static bool stdinIsTerminal() {
#ifdef _WIN32
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    return GetConsoleMode(hIn, &mode) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

// ---------------------------------------------------------------------------
//  Console helpers
// ---------------------------------------------------------------------------
std::string InputValidator::readLine(const std::string& prompt) {
    std::cout << prompt;
    std::string line;
    std::getline(std::cin, line);
    auto start = line.find_first_not_of(" \t\r\n");
    auto end   = line.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return line.substr(start, end - start + 1);
}

std::string InputValidator::readPassword(const std::string& prompt) {
    std::cout << prompt;
    std::string password;

    // If stdin is redirected/piped, just use getline (no masking possible)
    if (!stdinIsTerminal()) {
        std::getline(std::cin, password);
        return password;
    }

#ifdef _WIN32
    while (true) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            std::cout << '\n';
            break;
        } else if (ch == '\b' || ch == 127) {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch >= 32 && ch <= 126) {
            password.push_back(static_cast<char>(ch));
            std::cout << '*';
        }
    }
#else
    struct termios oldt{}, newt{};
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    std::getline(std::cin, password);
    std::cout << '\n';

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    return password;
}
