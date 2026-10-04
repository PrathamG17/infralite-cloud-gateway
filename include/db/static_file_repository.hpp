#pragma once

#include <vector>
#include <string>

#include "static_file.hpp"
#include "database_handler.hpp"

/** Persists route-to-file mappings for static content delivery. */
class StaticFileRepository
{
    private:
        DatabaseHandler* m_pDB;

    public:
        /** Binds the repository to an open database handler.
         * @param db Database connection and encryption service.
         * @return No value.
         */
        StaticFileRepository(DatabaseHandler* db);

        /** Creates the static-file table and migrates stored file paths.
         * @return True when schema creation and migration succeed.
         */
        bool CreateTable();

        /** Associates a route ID with a file path and content type.
         * @param routeId Route whose response serves the file.
         * @param filePath File path stored encrypted at rest.
         * @param contentType MIME type associated with the file.
         * @return True when the mapping is persisted successfully.
         */
        bool AddFile(int routeId, const std::string& filePath, const std::string& contentType);

        /** Soft-deletes a static-file mapping.
         * @param fileId File-mapping record to deactivate.
         * @return True when SQLite executes the update successfully.
         */
        bool RemoveFile(int fileId);

        /** Reads active mappings and decrypts their stored paths.
         * @return Active mappings; an empty vector is returned on query failure.
         */
        std::vector<StaticFile> GetFiles();
};
