#pragma once

#include "Program.h"
#include "Keystore.h"

#include <string>

class ProgramSelection : public ProgramVisitor
{
private:
    std::string _filename;
    ssize_t _key_idx;
    Keystore *_keystore;

public:
    ProgramSelection(const std::string &filename, ssize_t key_idx, Keystore *keystore);

    void visit(DecryptedProgram &prog) override;
    void visit(EncryptedProgram &prog) override;
    void visit(SignedEncryptedProgram &prog) override;

private:
    bool is_loaded(Program &prog);
    bool is_decrypted(Program &prog);
    bool is_verified(Program &prog);

    void program_info(Program &prog);

    void decrypted_menu();
    void encrypted_menu();
    void signed_encrypted_menu();

    void run_program(Program &prog);
    void decrypt_program(EncryptedProgram &prog);
    void verify_program(SignedEncryptedProgram &prog);
    void verify_decrypt_program(SignedEncryptedProgram &prog);
};
