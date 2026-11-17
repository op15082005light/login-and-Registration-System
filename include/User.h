#pragma once
// ============================================================================
//  User.h — Value object representing a single registered user
// ============================================================================

#include <cstdint>
#include <string>

class User {
public:
    User() = default;
    User(const std::string& username,
         const std::string& passwordHash,
         const std::string& salt,
         const std::string& createdAt);

    // Accessors
    const std::string& getUsername()     const;
    const std::string& getPasswordHash() const;
    const std::string& getSalt()        const;
    const std::string& getCreatedAt()   const;
    uint32_t           getLoginCount()  const;

    // Mutators
    void setPasswordHash(const std::string& hash);
    void setSalt(const std::string& salt);
    void incrementLoginCount();

    // Serialization  (pipe-delimited single line)
    std::string serialize() const;
    static User deserialize(const std::string& line);

private:
    std::string username_;
    std::string passwordHash_;
    std::string salt_;
    std::string createdAt_;
    uint32_t    loginCount_ = 0;
};
