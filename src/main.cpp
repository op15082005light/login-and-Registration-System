// ============================================================================
//  main.cpp — Entry point: main menu loop
// ============================================================================

#include "Auth.h"
#include "Dashboard.h"
#include "UserDatabase.h"

#include <iostream>
#include <string>

int main() {
    const std::string dataFile = "data/users.dat";

    UserDatabase db(dataFile);
    if (!db.load()) {
        std::cerr << "[FATAL] Could not load user database.\n";
        return 1;
    }

    Auth      auth(db);
    Dashboard dashboard(auth, db);

    std::cout << "==========================================\n"
              << "   LOGIN AND REGISTRATION SYSTEM (C++17)  \n"
              << "==========================================\n";

    bool running = true;
    while (running) {
        std::cout << "\n  [1] Register\n"
                  << "  [2] Login\n"
                  << "  [3] Exit\n";

        std::string choice;
        std::cout << "  Select > ";
        std::getline(std::cin, choice);

        if (choice == "1") {
            auth.registerUser();
        } else if (choice == "2") {
            std::string loggedInUser;
            if (auth.login(loggedInUser)) {
                dashboard.show(loggedInUser);
            }
        } else if (choice == "3") {
            std::cout << "  Goodbye!\n";
            running = false;
        } else {
            std::cout << "  [ERROR] Invalid option. Try 1, 2, or 3.\n";
        }
    }

    return 0;
}
