// ============================================================================
//  Dashboard.cpp — Post-login interactive menu
// ============================================================================

#include "Dashboard.h"
#include "InputValidator.h"

#include <iostream>

Dashboard::Dashboard(Auth& auth, UserDatabase& db)
    : auth_(auth), db_(db) {}

void Dashboard::displayWelcome(const std::string& username) const {
    std::cout << "\n======================================\n"
              <<   "       WELCOME TO YOUR DASHBOARD      \n"
              <<   "======================================\n"
              <<   "  Logged in as: " << username << "\n\n";
}

void Dashboard::viewAccountInfo(const std::string& username) const {
    User user;
    if (!db_.findUser(username, user)) {
        std::cout << "  [ERROR] Account not found.\n";
        return;
    }

    std::cout << "\n---------- Account Info ----------\n"
              << "  Username    : " << user.getUsername()   << '\n'
              << "  Created at  : " << user.getCreatedAt() << '\n'
              << "  Login count : " << user.getLoginCount() << '\n'
              << "  Password    : ******** (hashed)\n"
              << "----------------------------------\n";
}

void Dashboard::show(const std::string& username) {
    displayWelcome(username);

    bool running = true;
    while (running) {
        std::cout << "  [1] View Account Info\n"
                  << "  [2] Change Password\n"
                  << "  [3] Logout\n";

        std::string choice = InputValidator::readLine("  Select > ");

        if (choice == "1") {
            viewAccountInfo(username);
        } else if (choice == "2") {
            auth_.changePassword(username);
        } else if (choice == "3") {
            std::cout << "  Logging out...\n";
            running = false;
        } else {
            std::cout << "  [ERROR] Invalid option. Try 1, 2, or 3.\n";
        }
    }
}
