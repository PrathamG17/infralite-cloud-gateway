#pragma once
#ifndef FILE_HANDLER_HPP
#define FILE_HANDLER_HPP

#include <string>

#include "response.hpp"

/** Serves files whose canonical paths remain inside a configured static root. */
class FileHandler
{
public:
    /** Sets the directory used as the static-content root.
     * @param sDir Static root directory path.
     * @return No value.
     */
    FileHandler(const std::string& sDir);

    /** Reads and returns a file after checking root containment.
     * @param sPath Request path relative to the static root.
     * @return HTTP response containing file bytes or an error status.
     */
    HttpResponse ServeFile(const std::string& sPath) const;

    /** Returns the configured static directory.
     * @return Root directory path as stored by this handler.
     */
    std::string  GetStaticDir() const;

private:
    std::string sRootDir;
};

#endif
