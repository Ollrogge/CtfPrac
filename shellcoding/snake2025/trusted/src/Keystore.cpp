#include "Keystore.h"

#include <stdexcept>

Key::Key(std::vector<std::byte>::const_iterator &data) : _data_begin(data) {}

EVP_CIPHER_CTX *Key::decrypt_ctx(const std::byte iv[16]) const
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return nullptr;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (const unsigned char *)&*this->_data_begin, (const unsigned char *)iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

EVP_CIPHER_CTX *Key::decrypt_ctx(const std::array<std::byte, 16> &array) const
{
    return decrypt_ctx(array.data());
}

Keystore::Keystore(EVP_PKEY *verify_pkey) : _verify_pkey(verify_pkey), _max_key_count(0), _av_key_count(0), _data() {}

Keystore::~Keystore()
{
    EVP_PKEY_free(_verify_pkey);
    _data.clear();
}

uint8_t Keystore::add_key(const std::array<std::byte, 32> &key)
{
    if (this->_av_key_count + 1 > this->_max_key_count)
    {
        this->_data.resize(this->_data.size() + 32);
        this->_max_key_count++;
    }

    std::copy(key.begin(), key.end(), std::next(this->_data.begin(), this->_av_key_count * 32uL));
    this->_av_key_count++;

    return this->_av_key_count - 1;
}

const Key Keystore::get_key(uint8_t index) const
{
    std::vector<std::byte>::const_iterator it = std::next(this->_data.cbegin(), index * 32uL);

    if (std::next(it, 32) > this->_data.cend())
    {
        throw std::out_of_range("Key index out of range");
    }

    return Key(it);
}

size_t Keystore::key_count() const
{
    return this->_av_key_count;
}

const Key Keystore::operator[](size_t index) const
{
    return get_key(index);
}

EVP_MD_CTX *Keystore::verify_ctx() const
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return nullptr;

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, this->_verify_pkey) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}