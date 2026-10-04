#pragma once

#include <string>
#include <memory>

#include "db/sqlite3.h"
#include "db/field_encryption.hpp"

/** Owns the SQLite connection and optional AES-GCM field-encryption key. */
class DatabaseHandler
{
    private :
        sqlite3* m_pDB;
        std::unique_ptr<FieldEncryption> m_pEncryption;

    public :
        /** Initializes an unopened database handler. @return No value. */
        DatabaseHandler();

        /** Closes the SQLite connection before destruction. */
        ~DatabaseHandler();

        /** Opens or creates a SQLite database file.
         * @param sDBPath Filesystem path, or :memory: for an in-memory database.
         * @return True when SQLite opens the database successfully.
         */
        bool Open(const std::string& sDBPath);

        /** Closes the current connection when one is open.
         * @return No value.
         */
        void Close();

        /** Executes a SQL statement that does not return rows.
         * @param sSQL SQL statement to execute.
         * @return True when SQLite reports success.
         */
        bool Execute(const std::string& sSQL);

        /** Configures AES-256-GCM encryption for sensitive repository fields.
         * @param keyMaterial Stable deployment secret from which the key is derived.
         * @return No value; throws when key derivation cannot be initialized.
         */
        void SetEncryptionKey(const std::string& keyMaterial);

        /** Encrypts a sensitive field when encryption is configured.
         * @param value Plaintext value to store.
         * @return Versioned ciphertext, or the original value when no key is set.
         */
        std::string EncryptSensitive(const std::string& value) const;

        /** Decrypts a sensitive field when encryption is configured.
         * @param value Stored ciphertext or legacy plaintext value.
         * @return Plaintext value, or the original value when no key is set.
         */
        std::string DecryptSensitive(const std::string& value) const;

        /** Encrypts legacy plaintext values in a validated table column.
         * @param table SQLite table identifier containing the values.
         * @param idColumn Unique row identifier column.
         * @param valueColumn Sensitive text column to migrate.
         * @return True when every row was read and updated successfully.
         */
        bool EncryptLegacyTextColumn(const std::string& table,
            const std::string& idColumn, const std::string& valueColumn);

        /** Returns the underlying SQLite connection for prepared statements.
         * @return Connection pointer, or nullptr before Open succeeds.
         */
        sqlite3* GetDB();
};
