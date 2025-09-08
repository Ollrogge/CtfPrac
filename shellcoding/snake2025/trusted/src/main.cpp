#include "utils.h"
#include "Keystore.h"
#include "Program.h"
#include "ProgramSelection.h"

#include <iostream>
#include <memory>
#include <list>

struct ActiveProgram
{
    std::unique_ptr<Program> program;
    std::string filename;
    ssize_t key_idx;
};

Keystore *keystore;
std::list<ActiveProgram> programs;

__attribute__((constructor)) void init()
{
    std::setbuf(stdout, nullptr);
    std::setbuf(stderr, nullptr);
    std::setbuf(stdin, nullptr);

    std::ios::sync_with_stdio(true);
}

void main_menu()
{
    std::cout << "---==* Trusted *==---" << std::endl;
    std::cout << "1) Add Key" << std::endl;
    std::cout << "2) Add Program" << std::endl;
    std::cout << "3) Select Program" << std::endl;
    std::cout << "4) Quit" << std::endl;
    std::cout << "> ";
}

void add_key()
{
    std::string b64_key;
    std::cout << "Enter base64-encoded key > ";
    std::cin >> b64_key;

    std::vector<std::byte> key_data;
    if (decode_b64(b64_key, key_data) < 0 || key_data.size() < 32)
    {
        std::cout << "Invalid key format. Key must be base64-encoded and 32 bytes long" << std::endl;
        return;
    }

    std::array<std::byte, 32> key_array;
    std::move(key_data.begin(), std::next(key_data.begin(), 32), key_array.begin());

    keystore->add_key(key_array);
    std::cout << "Key added successfully. " << keystore->key_count() << " key(s) available" << std::endl;
}

void add_program()
{
    std::string b64_prog;

    std::cout << "Enter base64-encoded program > ";
    std::cin >> b64_prog;

    std::vector<std::byte> prog_data;
    if (decode_b64(b64_prog, prog_data) < 0)
    {
        std::cout << "Invalid program format. Program must be base64-encoded" << std::endl;
        return;
    }

    FILE *tmpfile = nullptr;
    std::string tmp_path = write_to_tmpfs(prog_data, tmpfile);
    if (!tmpfile)
    {
        std::cout << "Failed to write program to temporary file" << std::endl;
        return;
    }

    std::unique_ptr<Program> program = Program::load_program(tmpfile);
    if (!program)
    {
        std::cout << "Failed to load program. Unsupported format or corrupted" << std::endl;
        return;
    }

    ssize_t key_idx = -1;
    if (dynamic_cast<EncryptedProgram *>(program.get()))
    {

        if (keystore->key_count() == 0)
        {
            std::cout << "Encrypted program detected and no keys are available. Please add a key first" << std::endl;
            fclose(tmpfile);
            return;
        }

        std::cout << "Encrypted program detected. Please select the associated key slot (" << (keystore->key_count()) << " key(s) available) > ";
        key_idx = read_uint();
        if (key_idx < 0 || key_idx >= keystore->key_count())
        {
            std::cout << "Invalid key index" << std::endl;
            fclose(tmpfile);
            return;
        }
    }

    std::cout << "Program loaded successfully" << std::endl;

    programs.push_back({std::move(program), tmp_path, key_idx});
}

void select_program()
{
    if (programs.empty())
    {
        std::cout << "No programs available. Please add a program first" << std::endl;
        return;
    }
    std::cout << "Available Programs:" << std::endl;

    for (auto it = programs.begin(); it != programs.end(); ++it)
        std::cout << std::distance(programs.begin(), it) << ") " << it->filename << std::endl;

    std::cout << "Select a program (" << programs.size() << " program(s) available) > ";
    ssize_t idx = read_uint();
    if (idx < 0 || idx >= programs.size())
    {
        std::cout << "Invalid program index" << std::endl;
        return;
    }

    auto &[prog, filename, key_idx] = *std::next(programs.begin(), idx);

    ProgramSelection selector(filename, key_idx, keystore);
    prog->accept(selector);
}

void load_default_programs()
{
    auto ex_dec = Program::load_program("default_progs/ex_dec");
    auto ex_enc = Program::load_program("default_progs/ex_enc");
    auto ex_sig = Program::load_program("default_progs/ex_sig");

    auto ex_enc_key = load_key("default_progs/ex_enc.key");
    auto ex_sig_key = load_key("default_progs/ex_sig.key");

    auto ex_enc_key_idx = keystore->add_key(ex_enc_key);
    auto ex_sig_key_idx = keystore->add_key(ex_sig_key);

    programs.push_back({std::move(ex_dec), "default_progs/ex_dec", -1});
    programs.push_back({std::move(ex_enc), "default_progs/ex_enc", ex_enc_key_idx});
    programs.push_back({std::move(ex_sig), "default_progs/ex_sig", ex_sig_key_idx});
}

int main(int argc, char **argv)
{
    keystore = new Keystore(load_verify_key(safe_getenv("VERIFY_KEY", "public.pem")));

    load_default_programs();

    uint64_t choice = 0;
    do
    {
        main_menu();
        choice = read_uint();

        switch (choice)
        {
        case 1:
            add_key();
            break;
        case 2:
            add_program();
            break;
        case 3:
            select_program();
            break;
        case 4:
        default:
            break;
        }

    } while (choice != 4);
}