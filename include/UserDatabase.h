#pragma once
// ============================================================================
//  UserDatabase.h — Persistent storage of User records (file-backed)
// ============================================================================

#include "User.h"
#include <string>
#include <unordered_map>

class UserDatabase {
public:
    explicit UserDatabase(const std::string& filePath);

    // Load all records from disk; returns false on I/O error
    bool load();

    // Persist all records to disk; returns false on I/O error
    bool save() const;

    // Lookup
    bool hasUser(const std::string& username) const;

    // Returns true + fills 'out' if found; returns false if not found
    bool findUser(const std::string& username, User& out) const;

    // Mutation
    bool addUser(const User& user);           // false if duplicate
    bool updateUser(const User& user);        // false if not found

    size_t userCount() const;

private:
    std::string filePath_;
    std::unordered_map<std::string, User> users_;
};
