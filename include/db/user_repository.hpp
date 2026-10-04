#pragma once

#include <vector>

#include "db/user.hpp"
#include "database_handler.hpp"

/** Persists user identities, roles, and encrypted password hashes. */
class UserRepository
{
    private:
        DatabaseHandler* m_pDB;

    public:
        /** Binds the repository to an open database handler.
         * @param db Database connection and encryption service.
         * @return No value.
         */
        UserRepository(DatabaseHandler* db);

        /** Creates the user table and encrypts any legacy plaintext hashes.
         * @return True when schema creation and migration succeed.
         */
        bool CreateTable();

        /** Adds an active user with an encrypted password hash.
         * @param username Unique login name.
         * @param passwordHash Precomputed password hash, not the raw password.
         * @param role Assigned server role.
         * @return New user ID, or -1 when insertion fails.
         */
        int  AddUser(const std::string& username, const std::string& passwordHash, const std::string& role);

        /** Changes a user's role and optionally their password hash.
         * @param userId User record to update.
         * @param role New role value.
         * @param passwordHash New hash, or "unchanged" to retain the stored hash.
         * @return True when SQLite executes the update successfully.
         */
        bool UpdateUser(int userId, const std::string& role, const std::string& passwordHash);

        /** Soft-deletes a user by marking the account inactive.
         * @param userId User record to deactivate.
         * @return True when SQLite executes the update successfully.
         */
        bool DeleteUser(int userId);

        /** Reads active users and decrypts their stored password hashes.
         * @return Active user records; an empty vector is returned on query failure.
         */
        std::vector<User> GetUsers();
};
