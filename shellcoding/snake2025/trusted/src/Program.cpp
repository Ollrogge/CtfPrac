#include "Program.h"

#include <sys/mman.h>
#include <array>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdexcept>
#include <algorithm>

#include <openssl/evp.h>

Program::Program(FILE *file) : _flags(ProgramFlags::NONE), _size(0), _memfd(-1), _map_area(nullptr)
{
    this->_file = file;
}

Program::~Program()
{
    if (this->_map_area && this->_map_area != MAP_FAILED)
    {
        munmap(this->_map_area, this->_size);
    }
    if (this->_memfd >= 0)
    {
        close(this->_memfd);
    }
    if (this->_file)
    {
        fclose(this->_file);
    }
}

int Program::load()
{
    if (fseek(this->_file, 4, SEEK_SET) != 0)
        return -1;

    off_t curr_pos = ftell(this->_file);

    fseek(this->_file, 0, SEEK_END);
    this->_size = ftell(this->_file) - curr_pos;
    fseek(this->_file, curr_pos, SEEK_SET);

    if (this->_size == 0)
        return -1;

    this->_flags |= ProgramFlags::LOADED;
    return 0;
}

int Program::_map()
{
    this->_map_area = mmap(nullptr, this->_size, PROT_READ | PROT_WRITE, MAP_SHARED, this->_memfd, 0);
    return this->_map_area == MAP_FAILED ? -1 : 0;
}

int Program::_copy_to_memfd()
{
    this->_memfd = memfd_create("program", MFD_ALLOW_SEALING | MFD_EXEC);
    if (this->_memfd < 0)
        return -1;

    if (ftruncate(this->_memfd, this->_size) < 0)
        return -1;

    fcntl(this->_memfd, F_ADD_SEALS, F_SEAL_GROW);

    off_t curr_pos = ftell(this->_file);

    if (sendfile(this->_memfd, fileno(this->_file), &curr_pos, this->_size) < 0)
        return -1;

    return 0;
}

void *Program::map_address() const
{
    return this->_map_area;
}

int Program::flags() const
{
    return this->_flags;
}

ssize_t Program::size() const
{
    return this->_size;
}

int DecryptedProgram::load()
{
    if (this->Program::load() != 0)
    {
        return -1;
    }

    if (this->_copy_to_memfd() < 0)
    {
        this->_flags &= ~ProgramFlags::LOADED;
        return -1;
    }

    if (this->_map() != 0)
    {
        this->_flags &= ~ProgramFlags::LOADED;
        return -1;
    }

    return 0;
}

int DecryptedProgram::run(int *status)
{
    if (!this->can_run())
    {
        return -1;
    }

    pid_t pid = vfork();

    if (pid < 0)
    {
        return -2;
    }
    else if (pid == 0)
    {
        dup2(this->_memfd, 3);

        execlp("./wrapper", nullptr);
        _exit(1);
    }
    else
    {
        int wp_status;
        waitpid(pid, &wp_status, 0);
        if (WIFEXITED(wp_status))
        {
            *status = WEXITSTATUS(wp_status);
            return 0;
        }
    }

    return -3;
}

bool DecryptedProgram::can_run() const
{
    return (this->_flags & ProgramFlags::LOADED) != 0;
}

int EncryptedProgram::load()
{
    if (this->Program::load() != 0)
    {
        return -1;
    }

    if (this->_load_meta() != 0)
    {
        this->_flags &= ~ProgramFlags::LOADED;
        return -1;
    }

    if (this->_copy_to_memfd() < 0)
    {
        this->_flags &= ~ProgramFlags::LOADED;
        return -1;
    }

    if (this->_map() != 0)
    {
        this->_flags &= ~ProgramFlags::LOADED;
        return -1;
    }

    return 0;
}

std::array<std::byte, 16> EncryptedProgram::iv() const
{
    return this->_iv;
}

int EncryptedProgram::_load_meta()
{

    if (fread(this->_iv.data(), sizeof(std::byte), this->_iv.size(), this->_file) != this->_iv.size())
    {
        return -1;
    }

    this->_size -= this->_iv.size();

    if (this->_size <= 0)
    {
        return -1;
    }

    return 0;
}

int EncryptedProgram::decrypt(const Key &key)
{
    EVP_CIPHER_CTX *ctx = key.decrypt_ctx(_iv);
    if (!ctx)
    {
        return -1;
    }

    unsigned char *data = static_cast<unsigned char *>(this->_map_area);
    int out_len, final_len;

    if (EVP_DecryptUpdate(ctx, data, &out_len, data, this->_size) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_DecryptFinal_ex(ctx, data + out_len, &final_len);
    this->_size = out_len + final_len;

    ftruncate(this->_memfd, this->_size);

    mprotect(this->_map_area, this->_size, PROT_READ);
    fcntl(this->_memfd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL);

    this->_flags |= ProgramFlags::DECRYPTED;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

bool EncryptedProgram::can_run() const
{
    return this->DecryptedProgram::can_run() && (this->_flags & ProgramFlags::DECRYPTED) != 0;
}

int SignedEncryptedProgram::_load_meta()
{
    if (EncryptedProgram::_load_meta() < 0)
    {
        return -1;
    }

    if (fread(this->_signature.data(), sizeof(std::byte), this->_signature.size(), this->_file) != this->_signature.size())
    {
        return -1;
    }

    this->_size -= this->_signature.size();

    if (this->_size <= 0)
    {
        return -1;
    }

    std::transform(this->_signature.begin(), this->_signature.end(),
                   this->_signature.begin(),
                   [_iv = this->_iv, i = 0](std::byte b) mutable
                   {
                       return b ^ _iv[i++ % _iv.size()];
                   });

    return 0;
}

int SignedEncryptedProgram::run(int *status)
{
    if (mprotect(this->_map_area, this->_size, PROT_READ | PROT_EXEC) != 0)
    {
        return -1;
    }

    if (!this->can_run())
    {
        return -2;
    }

    int ret = 0;

    __asm__(
        ".intel_syntax noprefix;"
        "push rbx;"
        "push rbp;"
        "push r12;"
        "push r13;"
        "push r14;"
        "push r15;"
        "call %1;"
        "pop r15;"
        "pop r14;"
        "pop r13;"
        "pop r12;"
        "pop rbp;"
        "pop rbx;"
        ".att_syntax prefix;"
        : "=a"(ret)
        : "r"(this->_map_area)
        : "memory");

    *status = ret;

    if (mprotect(this->_map_area, this->_size, PROT_READ) != 0)
    {
        return -2;
    }

    return 0;
}

int SignedEncryptedProgram::verify(const VerifyKey &verify_key)
{
    EVP_MD_CTX *verify_ctx = verify_key.verify_ctx();
    if (!verify_ctx)
    {
        return -1;
    }

    const unsigned char *data = static_cast<const unsigned char *>(this->_map_area);
    const unsigned char *signature = reinterpret_cast<const unsigned char *>(this->_signature.data());

    size_t data_len = this->_size;
    size_t signature_len = this->_signature.size();

    if (EVP_DigestVerify(verify_ctx, signature, signature_len, data, data_len) != 1)
    {
        EVP_MD_CTX_free(verify_ctx);
        return -1;
    }

    this->_flags |= ProgramFlags::VERIFIED;

    EVP_MD_CTX_free(verify_ctx);
    return 0;
}

bool SignedEncryptedProgram::can_run() const
{
    return this->EncryptedProgram::can_run() && (this->_flags & ProgramFlags::VERIFIED) != 0;
}

void DecryptedProgram::accept(ProgramVisitor &visitor)
{
    visitor.visit(*this);
}

void EncryptedProgram::accept(ProgramVisitor &visitor)
{
    visitor.visit(*this);
}

void SignedEncryptedProgram::accept(ProgramVisitor &visitor)
{
    visitor.visit(*this);
}

std::unique_ptr<Program> Program::load_program(const char *name)
{
    FILE *file = fopen(name, "rb");
    if (!file)
    {
        return nullptr;
    }

    setbuf(file, nullptr);

    return Program::load_program(file);
}

std::unique_ptr<Program> Program::load_program(FILE *file)
{

    ProgramKind type;
    if (fread(&type, sizeof(type), 1, file) != 1)
    {
        fclose(file);
        return nullptr;
    }

    std::unique_ptr<Program> program;
    switch (type)
    {
    case ProgramKind::DEC_PROG:
        program.reset(new DecryptedProgram(file));
        break;
    case ProgramKind::ENC_PROG:
        program.reset(new EncryptedProgram(file));
        break;
    case ProgramKind::SIG_ENC_PROG:
        program.reset(new SignedEncryptedProgram(file));
        break;
    default:
        fclose(file);
        return nullptr;
    }

    if (program->load() != 0)
    {
        return nullptr;
    }

    return program;
}