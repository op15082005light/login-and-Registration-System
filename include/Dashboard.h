#pragma once
// ============================================================================
//  Dashboard.h — Post-login user dashboard
// ============================================================================

#include "Auth.h"
#include "UserDatabase.h"
#include <string>

class Dashboard {
public:
    Dashboard(Auth& auth, UserDatabase& db);

    // Show the dashboard loop; returns when the user logs out
    void show(const std::string& username);

private:
    void displayWelcome(const std::string& username) const;
    void viewAccountInfo(const std::string& username) const;

    Auth&         auth_;
    UserDatabase& db_;
};
