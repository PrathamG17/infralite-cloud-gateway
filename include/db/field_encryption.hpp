#pragma once

#include <array>
#include <string>

/** Provides authenticated AES-256-GCM encryption for persisted text fields. */
class FieldEncryption
{
private:
    std::array<unsigned char, 32> key{};

public:
    /** Derives a 256-bit key from deployment key material.
     * @param keyMaterial Secret input used to derive the AES key.
     * @return No value; throws when key setup fails.
     */
    explicit FieldEncryption(const std::string& keyMaterial);

    /** Encrypts text using a fresh nonce and authentication tag.
     * @param value Plaintext to encrypt.
     * @return Versioned, hex-encoded authenticated ciphertext.
     */
    std::string Encrypt(const std::string& value) const;

    /** Authenticates and decrypts a versioned ciphertext.
     * @param value Ciphertext produced by Encrypt, or legacy plaintext.
     * @return Decrypted plaintext; throws if ciphertext authentication fails.
     */
    std::string Decrypt(const std::string& value) const;

    /** Identifies values carrying this utility's ciphertext version prefix.
     * @param value Stored field value to inspect.
     * @return True when the value begins with a recognized encrypted prefix.
     */
    static bool IsEncrypted(const std::string& value);
};