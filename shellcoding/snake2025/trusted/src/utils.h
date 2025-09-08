#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <openssl/evp.h>

const char* safe_getenv(const char* name, const char* default_value = "");
uint64_t read_uint();
int decode_b64(const std::string& b64, std::vector<std::byte>& out);
std::string write_to_tmpfs(std::vector<std::byte>& data, FILE* &tmpfile);
std::array<std::byte, 32> load_key(const char *key_path);
EVP_PKEY* load_verify_key(const char* key_path);