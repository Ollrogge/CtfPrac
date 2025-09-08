#pragma once

#include <vector>
#include <array>
#include <cstddef>

#include <openssl/evp.h>
#include <openssl/aes.h>

class Key
{
    std::vector<std::byte>::const_iterator _data_begin;

protected:
    explicit Key(std::vector<std::byte>::const_iterator &data);

public:
    EVP_CIPHER_CTX *decrypt_ctx(const std::byte iv[16]) const;
    EVP_CIPHER_CTX *decrypt_ctx(const std::array<std::byte, 16> &array) const;

    friend class Keystore;
};

class VerifyKey
{
public:
    virtual EVP_MD_CTX *verify_ctx() const = 0;
};

class Keystore : public VerifyKey
{

    std::vector<std::byte> _data;

    uint8_t _max_key_count;
    uint8_t _av_key_count;

    EVP_PKEY *_verify_pkey;

public:
    Keystore(EVP_PKEY *verify_pkey);
    ~Keystore();

    uint8_t add_key(const std::array<std::byte, 32> &key);
    const Key get_key(uint8_t index) const;

    size_t key_count() const;

    const Key operator[](size_t index) const;

    EVP_MD_CTX *verify_ctx() const;
};