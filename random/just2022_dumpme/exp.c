#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <stdint.h>
#include <signal.h>
#include <linux/unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

#define PTRACE_WORD int64_t

#define errExit(ret) do { if (ret < 0) { perror(#ret); exit(-1); }} while(0)

#define LO_PAGE_ADDR(phdr) ((phdr)->p_offset & PAGE_MASK)
#define HI_PAGE_ADDR(phdr) (((phdr)->p_offset + ((phdr)->p_filesz) + PAGE_SIZE - 1) & PAGE_MASK)

#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define INTERSECTS(off1, size1, off2, size2) ( ((off1) < (off2)) ? ((off2) < (off1) + (size1)) : ((off1) < ((off2) + (size2))) )

typedef u_int64_t Elf64_Addr;
typedef u_int16_t Elf64_Half;
typedef u_int64_t Elf64_Off;
typedef u_int32_t Elf64_Word;
typedef u_int64_t Elf64_Lword;
typedef u_int64_t Elf64_Xword;

/* The ELF file header.  This appears at the start of every ELF file.  */

#define EI_NIDENT (16)

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

#define EI_CLASS        4               /* File class byte index */
#define ELFCLASS64      2               /* 64-bit objects */

/* Legal values for e_type (object file type).  */
#define ET_EXEC         2               /* Executable file */
#define ET_DYN          3               /* Shared object file */

/* Program segment header.  */

typedef struct {
    Elf64_Word p_type;
    Elf64_Word p_flags;
    Elf64_Off p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
} Elf64_Phdr;

/* Legal values for p_type (segment type).  */

#define PT_NULL         0               /* Program header table entry unused */
#define PT_LOAD         1               /* Loadable program segment */

/*----------------------------------------------------------------------------*/

/* this is the word datatype returned by ptrace for PEEK* */
#define PTRACE_WORD int64_t

#define NUM_ELF_HEADERS 10

static int
read_text_segment (pid_t pid, u_int64_t addr, char *buf, size_t num_bytes)
{
   int i;
   int num_words;

   printf("reading text segment \n");

   /* determine number of words required to read num_bytes */
   num_words = num_bytes / sizeof(PTRACE_WORD);
   if ((num_bytes % sizeof(PTRACE_WORD)) != 0)
      num_words++;

   for (i = 0; i < num_words; i++) {
      *(((PTRACE_WORD *) buf) + i ) = ptrace(PTRACE_PEEKTEXT, pid,
                                             addr + i * sizeof(PTRACE_WORD), 0);
      if (errno != 0) {
         char msg[1024];
         snprintf(msg, sizeof(msg), "ptrace(PTRACE_PEEKTEXT, pid, 0x%p, 0)",
                  addr + i * sizeof(PTRACE_WORD));
         perror(msg);
         return 0;
      }
   }

   return 1;
}

static u_int64_t
find_elf_header (pid_t pid)
{
   int i;
   char *elf_hdr = "\177ELF";
   Elf64_Ehdr hdr;
   u_int64_t possible[NUM_ELF_HEADERS];
   int num_possible;
   u_int64_t addr;
   PTRACE_WORD word;
   int found_elf_header;

   num_possible = 0;

   /* search each page to see if elf header is found */
   for (addr = 0x00001337babe000; addr < 0x7fffffffffffUL; addr += PAGE_SIZE) {
      found_elf_header = 0;
      word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
      if ((errno == 0) && ((word&0xffffffff) == (0xffffffff & *((PTRACE_WORD *) elf_hdr)))) {
         if (read_text_segment(pid, addr, (char *) &hdr, sizeof(hdr))) {
            if (hdr.e_type == ET_EXEC)
              found_elf_header = 1;
            else if (hdr.e_type == ET_DYN)
               printf("discarding shared library at "
                     "virtual memory address 0x%p\n", addr);
         }
      }
      if (found_elf_header) {
         if (num_possible == NUM_ELF_HEADERS) {
            printf("too many possible elf headers found (> %d)\n",
                    NUM_ELF_HEADERS);
            return 0;
         }
         possible[num_possible] = addr;
         num_possible++;

         /* The 32 bit version used to support having multiples       */
         /* The 64 bit address space is so large that, to avoid       */
         /* searching indefinteliy, it breaks as soon as one is found */
         break;
      }
   }

   if (num_possible == 0) {
      /* no elf header found */
      return 0;
   }
   else if (num_possible == 1) {
      /* a single elf header was found */
      fprintf(stdout, "using elf header at virtual memory address "
                      "         0x%p\n", possible[0]);
      return possible[0];
   }
   else {
      /* need to resolve conflicts - let user decide */
      fprintf(stderr, "multiple elf headers found:\n");
      for (i = 0; i < num_possible; i++) {
         printf("  0x%p\n", possible[i]);
      }
      return 0;
   }
}

static void
warn_lost_data (pid_t pid, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr,
                u_int64_t offset, u_int64_t size)
{
   static u_int64_t last_offset = 0;   /* for recording last offset */
   static u_int64_t last_size = 0;     /* and size - initialised to zero */
   int p;

   if (offset != 0 && size != 0) {
      if ((last_offset + last_size) == offset) {
         /* join offsets */
         last_size += size;
         return;
      }
   }

   if (last_offset != 0 && last_size != 0) {
      fprintf(stderr, "could not recover data - %ld bytes at file offset %ld\n",
              last_size, last_offset);

      for (p = 0; p < ehdr->e_phnum; p++) {
         if (phdr[p].p_type != PT_NULL) {
            if (INTERSECTS(last_offset, last_size,
                           phdr[p].p_offset, phdr[p].p_filesz))
            {
               fprintf(stderr, " ! data from phdr[%d] was not recovered\n", p);
            }
         }
      }

      if ((ehdr->e_shnum != 0) &&
           INTERSECTS(last_offset, last_size, ehdr->e_shoff,
                      ehdr->e_shnum * ehdr->e_shentsize))
      {
         fprintf(stderr, " ! section header table was not recovered\n");
      }
   }

   /* record this offset and size */
   last_offset = offset;
   last_size   = size;
}

static int
create_file (char *filename, pid_t pid, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr,
             size_t file_size)
{
   FILE *fptr;
   Elf64_Phdr *this_phdr;
   char page[PAGE_SIZE];
   int i, p;
   int num_pages;
   u_int64_t *pages;
   u_int64_t end_segment_address;
   int okay, last_page;


   num_pages = (file_size + PAGE_SIZE - 1) / PAGE_SIZE;
   pages = malloc(num_pages * sizeof(*pages));

   if (pages == NULL) {
      fprintf(stderr, "malloc failed\n");
      return 0;
   }

   /* map memory pages to position in file */
   for (i = 0; i < num_pages; i++) {
      pages[i] = 0;
      for (p = 0; p < ehdr->e_phnum; p++) {
         this_phdr = &phdr[p];
         if (this_phdr->p_type == PT_LOAD) {
            if (LO_PAGE_ADDR(this_phdr) <= (i * PAGE_SIZE) &&
                  ((i + 1) * PAGE_SIZE) <= HI_PAGE_ADDR(this_phdr))
            {
               /* check for lost data in the last page of the segment */
               end_segment_address = this_phdr->p_offset + this_phdr->p_filesz;
               last_page = end_segment_address < ((i + 1) * PAGE_SIZE);
               if (last_page && (this_phdr->p_memsz > this_phdr->p_filesz)) {
                  warn_lost_data(pid, ehdr, phdr, end_segment_address,
                                 ((i + 1) * PAGE_SIZE) - end_segment_address);
               }

               pages[i] = phdr[p].p_vaddr - phdr[p].p_offset + (i * PAGE_SIZE);
               break;
            }
         }
      }

      /* warn about lost data if no memory page maps to file */
      if (pages[i] == 0)
         warn_lost_data(pid, ehdr, phdr, i * PAGE_SIZE, PAGE_SIZE);
   }
   /* signal that an attempt to recover all pages has been made */
   warn_lost_data(pid, ehdr, phdr, 0, 0);

   /* write memory pages to file */
   okay = 0;
   if ( (fptr = fopen(filename, "wb")) != NULL) {
      for (i = 0; i < num_pages; i++) {
         if (pages[i] != 0) {
            if (! read_text_segment(pid, pages[i], page, PAGE_SIZE)) {
               fclose(fptr);
               free(pages);
               return 0;
            }
         }
         else {
            memset(page, '\0', PAGE_SIZE);
         }
         fwrite(page, 1, MIN(file_size, PAGE_SIZE), fptr);
         file_size -= PAGE_SIZE;
      }

      fclose(fptr);
      okay = 1;
   }
   else {
      char msg[1024];
      snprintf(msg, sizeof(msg), "couldn't create file `%s'", filename);
      perror(msg);
   }

   free(pages);

   return okay;
}

static int
save_to_file (char *filename, pid_t pid, u_int64_t addr, size_t file_size)
{
   char page[PAGE_SIZE];
   Elf64_Ehdr *ehdr;
   Elf64_Phdr *phdr;
   int okay;

   okay = 0;
   if (read_text_segment(pid, addr, page, PAGE_SIZE)) {
      /* ensure 64bit elf binary */
      ehdr = (Elf64_Ehdr *) page;
      if (page[EI_CLASS] == ELFCLASS64 && ehdr->e_type == ET_EXEC) {

         /* ensure program header table is in same page as elf header */
         if ((ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize) < PAGE_SIZE) {
            phdr = (Elf64_Phdr *) (page + ehdr->e_phoff);
            okay = create_file(filename, pid, ehdr, phdr, file_size);
         }
         else {
            fprintf(stderr, "program header table could not be found\n");
         }
      }
      else {
         fprintf(stderr, "no 64bit elf executable, found at addr 0x%p\n",
                 addr);
      }
   }

   return okay;
}

// finds 0x1337babe000
void search_memory(pid_t pid) {
        for (unsigned long addr = 0xf550000000UL; addr < 0x7fffffffffffUL; addr += 0x1000) {
                errno = 0;
                unsigned long res = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
                if (errno == 0) {
                        printf("FOUND: %lx\n", addr);
                        break;
                }
                if (addr % 0x10000000 == 0) {
                        printf("Searching... %lx\n", addr);
                }
        }
}

static void dump_registers(pid_t pid) {
        struct user_regs_struct regs = {0};
        errExit(ptrace(PTRACE_GETREGS, pid, NULL, &regs));
        printf("rdi: %016lx\t", regs.rdi);
        printf("rsi: %016lx\t", regs.rsi);
        printf("rdx: %016lx\t", regs.rdx);
        printf("rcx: %016lx\t", regs.rcx);
        printf("rax: %016lx\t", regs.rax);
        printf("orig_rax: %016lx\t", regs.orig_rax);
        printf("r8:  %016lx\n", regs.r8);
        printf("r9:  %016lx\t", regs.r9);
        printf("r10: %016lx\t", regs.r10);
        printf("r11: %016lx\t", regs.r11);
        printf("rbx: %016lx\t", regs.rbx);
        printf("rbp: %016lx\t", regs.rbp);
        printf("r12: %016lx\n", regs.r12);
        printf("r13: %016lx\t", regs.r13);
        printf("r14: %016lx\t", regs.r14);
        printf("r15: %016lx\t", regs.r15);
        printf("rip: %016lx\t", regs.rip);
        printf("rsp: %016lx\n", regs.rsp);
}

static void poke_syscall(pid_t pid) {
        int status = 0;
        unsigned long rip = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*RIP, 0);
        printf("Poking RIP: %lx\n", rip);
        errExit(ptrace(PTRACE_POKEUSER, pid, sizeof(long)*RAX, __NR_prctl));
        errExit(ptrace(PTRACE_POKEUSER, pid, sizeof(long)*RDI, PR_SET_DUMPABLE));
        errExit(ptrace(PTRACE_POKEUSER, pid, sizeof(long)*RSI, 1));
        errExit(ptrace(PTRACE_SINGLESTEP, pid, 0, 0));
}

static void make_dumpable(pid_t pid) {
    int status;
    // wait for sigstop
    if (waitpid(pid, &status, WUNTRACED) == pid) {
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
            errExit(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC));
            errExit(ptrace(PTRACE_CONT, pid, 0 , 0));

            // wait for exec
            waitpid(pid, &status, 0);
            printf("stop status: %d\n", WSTOPSIG(status));

            for (int i = 0; i < 10; i++) {
                if (i == 0x5) {
                    poke_syscall(pid);
                } else {
                    errExit(ptrace(PTRACE_SINGLESTEP, pid, 0, 0));
                }
                waitpid(pid, &status, 0);
                if (WIFEXITED(status)) {
                        printf("Process exited: %d\n", WTERMSIG(status));
                        exit(-2);
                }

                printf("%d\n", i);
                dump_registers(pid);
            }
        }
        else {
            puts("Stop status not SIGTRAP");
            exit(-1);
        }
    }
    else {
        puts("unexpected pid in waitpid");
        exit(-1);
    }
}

int main() {
    struct user_regs_struct regs;
    int status, signum;
    int ret = 0;
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* To avoid the need for CAP_SYS_ADMIN */
        errExit(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
        errExit(personality(ADDR_NO_RANDOMIZE));
        kill(getpid(), SIGSTOP);

        return execl("/task/dumpme", "/task/dumpme", NULL);
    }
    else {
        make_dumpable(pid);
        char out_filename[] = {"/tmp/out"};
        struct stat stats;

        if (stat("/task/dumpme", &stats) != 0) {
            perror("stat file");
            exit(EXIT_FAILURE);
        }

        uint64_t addr = find_elf_header(pid);

        if (save_to_file(out_filename, pid, addr, stats.st_size)) {
            chmod(out_filename, 00755);
            puts("created file :)");
        }
    }
    return 0;
}

// justCTF{tr4cing_blind_a1nt_that_h4rd}
