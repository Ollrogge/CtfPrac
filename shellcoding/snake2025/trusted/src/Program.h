#pragma once

#include <iostream>
#include <memory>
#include <array>

#include "Keystore.h"

class ProgramVisitor;

enum ProgramFlags
{
    NONE = 0,
    LOADED = 1 << 0,
    DECRYPTED = 1 << 1,
    VERIFIED = 1 << 2
};

enum ProgramKind : int
{
    DEC_PROG = 1,
    ENC_PROG = 2,
    SIG_ENC_PROG = 3
};

class Program
{
protected:
    FILE *_file;
    int _flags;
    ssize_t _size;
    int _memfd;
    void *_map_area;

public:
    Program(FILE *file);
    virtual ~Program();
    virtual int load();
    virtual int run(int *status) = 0;
    virtual bool can_run() const = 0;

    static std::unique_ptr<Program> load_program(const char *name);
    static std::unique_ptr<Program> load_program(FILE *file);

    virtual void accept(ProgramVisitor &visitor) = 0;

    void *map_address() const;
    int flags() const;
    ssize_t size() const;

protected:
    int _copy_to_memfd();
    int _map();
};

class DecryptedProgram : public Program
{

protected:
    DecryptedProgram(FILE *file) : Program(file) {}

    int load() override;
    bool can_run() const override;

public:
    int run(int *status) override;

    void accept(ProgramVisitor &visitor) override;

    friend std::unique_ptr<Program> Program::load_program(FILE *file);
};

class EncryptedProgram : public DecryptedProgram
{
protected:
    std::array<std::byte, 16> _iv;

    EncryptedProgram(FILE *file) : DecryptedProgram(file) {}

public:
    int load() override;
    virtual int decrypt(const Key &key);
    bool can_run() const override;

    std::array<std::byte, 16> iv() const;

protected:
    virtual int _load_meta();

public:
    void accept(ProgramVisitor &visitor) override;

    friend std::unique_ptr<Program> Program::load_program(FILE *file);
};

class SignedEncryptedProgram : public EncryptedProgram
{
protected:
    std::array<std::byte, 64> _signature;

    SignedEncryptedProgram(FILE *file) : EncryptedProgram(file) {}

public:
    int run(int *status) override;
    virtual int verify(const VerifyKey &verify_key);
    bool can_run() const override;

protected:
    int _load_meta() override;

public:
    void accept(ProgramVisitor &visitor) override;

    friend std::unique_ptr<Program> Program::load_program(FILE *file);
};

class ProgramVisitor
{
public:
    virtual ~ProgramVisitor() = default;

    virtual void visit(DecryptedProgram &prog) = 0;
    virtual void visit(EncryptedProgram &prog) = 0;
    virtual void visit(SignedEncryptedProgram &prog) = 0;
};