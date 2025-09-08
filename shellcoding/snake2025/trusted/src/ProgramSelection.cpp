#include "ProgramSelection.h"
#include "utils.h"

#include <iostream>
#include <iomanip>

ProgramSelection::ProgramSelection(const std::string &filename, ssize_t key_idx, Keystore *keystore)
    : _filename(filename), _key_idx(key_idx), _keystore(keystore) {}

void ProgramSelection::visit(DecryptedProgram &prog)
{
    uint64_t choice = 0;
    do
    {
        std::cout << "====== Decrypted Program ======" << std::endl;
        program_info(prog);
        std::cout << std::endl;
        decrypted_menu();

        std::cout << "> ";
        choice = read_uint();

        switch (choice)
        {
        case 1:
            run_program(prog);
            break;
        case 2:
            break;
        default:
            std::cout << "Invalid choice" << std::endl;
            break;
        }
    } while (choice != 2);
}

void ProgramSelection::visit(EncryptedProgram &prog)
{
    uint64_t choice = 0;
    do
    {
        std::cout << "====== Encrypted Program ======" << std::endl;
        program_info(prog);
        std::cout << std::endl;
        encrypted_menu();

        std::cout << "> ";
        choice = read_uint();

        switch (choice)
        {
        case 1:
            run_program(prog);
            break;
        case 2:
            decrypt_program(prog);
            break;
        case 3:
            break;
        default:
            std::cout << "Invalid choice" << std::endl;
            break;
        }
    } while (choice != 3);
}

void ProgramSelection::visit(SignedEncryptedProgram &prog)
{
    uint64_t choice = 0;
    do
    {
        std::cout << "====== Signed Encrypted Program ======" << std::endl;
        program_info(prog);
        std::cout << std::endl;
        signed_encrypted_menu();

        std::cout << "> ";
        choice = read_uint();

        switch (choice)
        {
        case 1:
            run_program(prog);
            break;
        case 2:
            verify_decrypt_program(prog);
            break;
        case 3:
            break;
        default:
            std::cout << "Invalid choice" << std::endl;
            break;
        }
    } while (choice != 3);
}

void ProgramSelection::program_info(Program &prog)
{
    std::cout << "Filename: " << this->_filename << std::endl;

    void *map_addr = prog.map_address();
    std::cout << "Load Address: " << std::hex << (map_addr ? map_addr : "N/A") << std::dec << std::endl;

    std::cout << "Program Size: " << prog.size() << " bytes" << std::endl;

    std::cout << "Status: "
              << (is_loaded(prog) ? "LOADED" : "")
              << (is_verified(prog) ? " VERIFIED" : "")
              << (is_decrypted(prog) ? " DECRYPTED" : "")
              << std::endl;

    EncryptedProgram *e_prog = nullptr;
    if ((e_prog = dynamic_cast<EncryptedProgram *>(&prog)))
    {
        std::cout << "IV: " << std::hex;

        for (auto &iv_byte : e_prog->iv())
            std::cout << std::setw(2) << std::setfill('0') << static_cast<unsigned>(iv_byte);

        std::cout << std::dec << std::endl;
    }
}

bool ProgramSelection::is_loaded(Program &prog)
{
    return (prog.flags() & ProgramFlags::LOADED) != 0;
}

bool ProgramSelection::is_decrypted(Program &prog)
{
    return (prog.flags() & ProgramFlags::DECRYPTED) != 0;
}

bool ProgramSelection::is_verified(Program &prog)
{
    return (prog.flags() & ProgramFlags::VERIFIED) != 0;
}

void ProgramSelection::decrypted_menu()
{
    std::cout << "1) Run Program" << std::endl;
    std::cout << "2) Go back" << std::endl;
}

void ProgramSelection::encrypted_menu()
{
    std::cout << "1) Run Program" << std::endl;
    std::cout << "2) Decrypt Program" << std::endl;
    std::cout << "3) Go back" << std::endl;
}

void ProgramSelection::signed_encrypted_menu()
{
    std::cout << "1) Run Program" << std::endl;
    std::cout << "2) Verify & Decrypt Program" << std::endl;
    std::cout << "3) Go back" << std::endl;
}

void ProgramSelection::run_program(Program &prog)
{
    int status = 0;

    int result = prog.run(&status);

    if (result == -1)
    {
        std::cout << "Failed to run program because it has not been verified/decrypted" << std::endl;
    }
    else if (result == -2)
    {
        std::cout << "Failed to run program because it could not be set up" << std::endl;
    }
    else if (result < -2)
    {
        std::cout << "Failed to run program due to an unknown error: " << result << std::endl;
    }
    else if (result == 0)
    {
        std::cout << "Program executed successfully with status " << status << std::endl;
    }
}

void ProgramSelection::decrypt_program(EncryptedProgram &prog)
{
    if (is_decrypted(prog))
    {
        std::cout << "Program is already decrypted" << std::endl;
        return;
    }

    const Key key = this->_keystore->get_key(this->_key_idx);
    int result = prog.decrypt(key);

    if (result < 0)
    {
        std::cout << "Decryption failed" << std::endl;
    }
    else
    {
        std::cout << "Decrypted successfully" << std::endl;
    }
}

void ProgramSelection::verify_program(SignedEncryptedProgram &prog)
{
    if (is_verified(prog))
    {
        std::cout << "Program is already verified" << std::endl;
        return;
    }

    int result = prog.verify(*this->_keystore);
    if (result < 0)
    {
        std::cout << "Invalid signature detected" << std::endl;
    }
    else
    {
        std::cout << "Valid signature found" << std::endl;
    }
}

void ProgramSelection::verify_decrypt_program(SignedEncryptedProgram &prog)
{
    verify_program(prog);
    decrypt_program(prog);
}
