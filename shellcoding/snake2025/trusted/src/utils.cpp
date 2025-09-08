#include "utils.h"

#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include <vector>
#include <array>
#include <string>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/decoder.h>

const char *safe_getenv(const char *name, const char *default_value)
{
    const char *value = getenv(name);
    return value ? value : default_value;
}

std::string write_to_tmpfs(std::vector<std::byte> &data, FILE *&tmpfile)
{
    char tmp_template[] = "/tmp/prog_XXXXXX";

    int tmpfd = mkstemp(tmp_template);
    if (tmpfd == -1)
    {
        throw std::runtime_error("Failed to create temporary file");
    }

    tmpfile = fdopen(tmpfd, "r+b");
    if (!tmpfile)
    {
        close(tmpfd);
        throw std::runtime_error("Failed to open temporary file");
    }

    fwrite(data.data(), sizeof(std::byte), data.size(), tmpfile);
    fflush(tmpfile);
    fseek(tmpfile, 0, SEEK_SET);

    return std::string(tmp_template);
}

uint64_t read_uint()
{
    uint64_t val = 0;
    std::cin >> val;

    if (!std::cin.good())
    {
        throw std::runtime_error("I/O Error");
    }
    std::cin.clear();

    return val;
}

int decode_b64(const std::string &b64, std::vector<std::byte> &out)
{
    if (b64.empty() || b64.size() % 4 != 0)
    {
        return -1;
    }

    out.resize(b64.size() * 3 / 4);

    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (!ctx)
    {
        return -1;
    }

    EVP_DecodeInit(ctx);

    int update_size = 0;
    if (EVP_DecodeUpdate(ctx, reinterpret_cast<unsigned char *>(out.data()), &update_size,
                         reinterpret_cast<const unsigned char *>(b64.data()), (int)b64.size()) < 0)
    {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }

    int final_size = 0;
    if (EVP_DecodeFinal(ctx, reinterpret_cast<unsigned char *>(out.data()) + update_size, &final_size) != 1)
    {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }

    out.resize(update_size + final_size);
    EVP_ENCODE_CTX_free(ctx);
    return 0;
}

std::array<std::byte, 32> load_key(const char *key_path)
{
    std::array<std::byte, 32> key{};
    std::fstream key_file(key_path, std::ios::in | std::ios::binary);
    if (!key_file)
    {
        throw std::runtime_error("Failed to open key file: " + std::string(key_path));
    }

    key_file.read(reinterpret_cast<char *>(key.data()), key.size());
    if (!key_file)
    {
        throw std::runtime_error("Failed to read key file: " + std::string(key_path));
    }

    return key;
}

EVP_PKEY *load_verify_key(const char *key_path)
{
    OSSL_DECODER_CTX *dCtx;
    EVP_PKEY *pkey;
    FILE *key_file;

    dCtx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, "ed25519", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);

    if (!dCtx)
    {
        throw std::runtime_error("Failed to create OSSL_DECODER_CTX");
    }

    key_file = fopen(key_path, "r");
    if (!key_file)
    {
        throw std::runtime_error("Failed to open key file: " + std::string(key_path));
    }

    if (OSSL_DECODER_from_fp(dCtx, key_file) != 1)
    {
        OSSL_DECODER_CTX_free(dCtx);
        fclose(key_file);
        throw std::runtime_error("Failed to decode public key from file: " + std::string(key_path));
    }

    OSSL_DECODER_CTX_free(dCtx);
    fclose(key_file);
    return pkey;
}