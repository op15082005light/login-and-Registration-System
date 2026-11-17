// ============================================================================
//  UserDatabase.cpp — File-backed user storage with safe I/O
// ============================================================================

#include "UserDatabase.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>

UserDatabase::UserDatabase(const std::string& filePath)
    : filePath_(filePath) {}

bool UserDatabase::load() {
    std::ifstream file(filePath_);
    if (!file.is_open()) {
        // File may not exist on first run — that is OK
        return true;
    }

    users_.clear();
    std::string line;
    int lineNum = 0;

    while (std::getline(file, line)) {
        ++lineNum;
        if (line.empty()) continue;
        try {
            User user = User::deserialize(line);
            users_[user.getUsername()] = user;
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Skipping corrupted record on line "
                      << lineNum << ": " << e.what() << '\n';
        }
    }

    if (file.bad()) {
        std::cerr << "[ERROR] I/O error while reading " << filePath_ << '\n';
        return false;
    }
    return true;
}

bool UserDatabase::save() const {
    const std::string tmpPath = filePath_ + ".tmp";

    {
        std::ofstream file(tmpPath, std::ios::trunc);
        if (!file.is_open()) {
            std::cerr << "[ERROR] Cannot open " << tmpPath << " for writing.\n";
            return false;
        }

        for (const auto& pair : users_) {
            file << pair.second.serialize() << '\n';
        }

        if (file.fail()) {
            std::cerr << "[ERROR] Write error to " << tmpPath << '\n';
            return false;
        }
    }

    std::remove(filePath_.c_str());
    if (std::rename(tmpPath.c_str(), filePath_.c_str()) != 0) {
        std::cerr << "[ERROR] Failed to rename temp file to " << filePath_ << '\n';
        return false;
    }
    return true;
}

bool UserDatabase::hasUser(const std::string& username) const {
    return users_.count(username) > 0;
}

bool UserDatabase::findUser(const std::string& username, User& out) const {
    auto it = users_.find(username);
    if (it != users_.end()) {
        out = it->second;
        return true;
    }
    return false;
}

bool UserDatabase::addUser(const User& user) {
    if (hasUser(user.getUsername())) return false;
    users_[user.getUsername()] = user;
    return save();
}

bool UserDatabase::updateUser(const User& user) {
    if (!hasUser(user.getUsername())) return false;
    users_[user.getUsername()] = user;
    return save();
}

size_t UserDatabase::userCount() const {
    return users_.size();
}
