// ============================================================================
//  User.cpp — Serialization / deserialization of User records
// ============================================================================

#include "User.h"
#include <sstream>
#include <stdexcept>

User::User(const std::string& username,
           const std::string& passwordHash,
           const std::string& salt,
           const std::string& createdAt)
    : username_(username),
      passwordHash_(passwordHash),
      salt_(salt),
      createdAt_(createdAt),
      loginCount_(0) {}

const std::string& User::getUsername()     const { return username_; }
const std::string& User::getPasswordHash() const { return passwordHash_; }
const std::string& User::getSalt()        const { return salt_; }
const std::string& User::getCreatedAt()   const { return createdAt_; }
uint32_t           User::getLoginCount()  const { return loginCount_; }

void User::setPasswordHash(const std::string& hash) { passwordHash_ = hash; }
void User::setSalt(const std::string& salt)         { salt_ = salt; }
void User::incrementLoginCount()                     { ++loginCount_; }

// Format: username|hash|salt|createdAt|loginCount
std::string User::serialize() const {
    std::ostringstream oss;
    oss << username_ << '|'
        << passwordHash_ << '|'
        << salt_ << '|'
        << createdAt_ << '|'
        << loginCount_;
    return oss.str();
}

User User::deserialize(const std::string& line) {
    std::istringstream iss(line);
    std::string token;
    std::string fields[5];
    int idx = 0;

    while (std::getline(iss, token, '|') && idx < 5) {
        fields[idx++] = token;
    }

    if (idx < 5) {
        throw std::runtime_error("Corrupted user record: " + line);
    }

    User u(fields[0], fields[1], fields[2], fields[3]);
    u.loginCount_ = static_cast<uint32_t>(std::stoul(fields[4]));
    return u;
}
