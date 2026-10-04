#pragma once

#include <string>

/** Active or inactive user record loaded from SQLite. */
struct User
{
    int userId;
    std::string username;
    std::string passwordHash;
    std::string role;
    std::string createdAt;
    int isActive;
};
