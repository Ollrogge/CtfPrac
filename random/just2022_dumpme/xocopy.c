/* xocopy - Program for copying an executable with execute but no read perms.
 * Copyright (C) 2002, 2003 Dion Mendel.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * A simple program to obtain a readable copy of an executable which has
 * execute, but no read permission.  It works by executing the process
 * - to load the process into memory - then dumping the memory image.
 *
 * Does not work for suid apps under linux 2.2.x.
 * Only works for elf files for which the elf header and program header table
 * are part of the loadable text segment (default for gcc).
 *
 * Generally, any data that appears in the file after loadable segments that
 * extend their size (usually shdr) will not be recovered.
 *
 * NOTE: This is a proof of concept program.  It is not robust.
 * NOTE: Does not work on linux kernels between 2.4.21-pre6 .. 2.4.21-rc2
 *       due to an incorrect ptrace patch being applied to those kernels.
 */

/* undefine this if there is no elf.h file on the system */
#define HAVE_ELF_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#ifdef HAVE_ELF_H
# include <elf.h>
#endif

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/*----------------------------------------------------------------------------*/
#ifdef __FreeBSD__
# define PTRACE_PEEKTEXT PT_READ_I
# define PTRACE_PEEKDATA PT_READ_D
# define PTRACE_TRACEME  PT_TRACE_ME
# define PTRACE_KILL     PT_KILL
#endif /* __FreeBSD__ */
/*----------------------------- ELF Definition -------------------------------*/
#ifndef HAVE_ELF_H

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

#endif     /* Elf Definition */
/*----------------------------------------------------------------------------*/

/* this is the word datatype returned by ptrace for PEEK* */
#define PTRACE_WORD int64_t

/*
 * PAGE_SIZE    - the size of a memory page
 * LO_USER      - the lowest address accessible from user space  (% PAGE_SIZE)
 * HI_USER      - the highest address accessible from user space  (% PAGE_SIZE)
 */
#if defined (__linux__)
#  define PAGE_SIZE 4096U
#  define LO_USER   4096U
#  define HI_USER   0x800000000000UL
#elif defined (__FreeBSD__)
#  define PAGE_SIZE 4096U
#  define LO_USER   4096U
#  define HI_USER   0xbfc00000U
#else
   ERROR UNKNOWN OPERATING SYSTEM
#endif

#define PAGE_MASK               (~(PAGE_SIZE-1))

/* ---------------- useful functions possibly found in libc ---------------- */

static char *
basename (char *pathname)
{
   char *ptr;
   ptr = strrchr(pathname, '/');
   return ptr ? ptr + 1 : pathname;
}

static int
tolower (int c)
{
   if ('A' <= c && c <= 'Z')
      return c + 'a' - 'A';
   return c;
}

/*
 * Reads a given number of bytes from the text segment.
 * num_bytes must be a multiple of the word size
 */
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

/*---------------------------------------------------------------------------*/

#define LO_PAGE_ADDR(phdr) ((phdr)->p_offset & PAGE_MASK)
#define HI_PAGE_ADDR(phdr) (((phdr)->p_offset + ((phdr)->p_filesz) + PAGE_SIZE - 1) & PAGE_MASK)

#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define INTERSECTS(off1, size1, off2, size2) ( ((off1) < (off2)) ? ((off2) < (off1) + (size1)) : ((off1) < ((off2) + (size2))) )

/*
 * Prints warning message for the bytes in the file that couldn't be recovered.
 * Uses 0/0 for offset/size to signal end of all lost data.
 */
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

/*
 * Writes the memory pages to the given filename.  Requires that ehdr and phdr
 * are in loaded memory.
 */
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

/*
 * Error check before writing the memory pages to disk.
 */
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


#define NUM_ELF_HEADERS 10

/*
 * Searches memory for an elf header.
 */
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
   for (addr = LO_USER; addr < HI_USER; addr += PAGE_SIZE) {
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

int
main (int argc, char *argv[])
{
   char *filename;
   char out_filename[8192];
   char buf[1024];
   struct stat stat_buf;
   pid_t pid;
   int status;
   int ret_val;
   size_t file_size;
   u_int64_t addr;
   int bad_usage;

   filename = NULL;
   addr = 0;

   /* process args: assigning values to bad_usage filename and possibly addr */
   bad_usage = 1;
   if (argc == 2) {
      filename = argv[1];
      bad_usage = 0;
   }
   else if (argc == 4) {
      filename = argv[3];

      if (strcmp(argv[1], "-a") == 0) {
         if ((argv[2][0] == '0') && (tolower(argv[2][1]) == 'x'))
            addr = strtol(argv[2], NULL, 16);
         else
            addr = strtol(argv[2], NULL, 10);
         if (errno != ERANGE)
            bad_usage = 0;
      }
   }

   if (bad_usage) {
      fprintf(stderr, "Obtains an executable copy of a binary with execute "
                      "but no read permission\n"
                      "Usage: %s [-a addr] <file>\n"
                      "  where addr is the memory address of the elf header\n",
                      argv[0]);
      exit(EXIT_FAILURE);
   }


   if (stat(filename, &stat_buf) != 0) {
      snprintf(buf, sizeof(buf), "couldn't stat file `%s'", filename);
      perror(buf);
      exit(EXIT_FAILURE);
   }

   /* remember file size of original file */
   file_size = stat_buf.st_size;

   if ( (pid = fork()) == 0) {
      /* child */
      if (ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) {
         execl(filename, filename, NULL);
         snprintf(buf, sizeof(buf), "couldn't exec `%s'", filename);
         perror(buf);
      }
      else {
         perror("ptrace(PTRACE_TRACEME, ...)");
      }
      _exit(EXIT_FAILURE);
   }

   ret_val = EXIT_FAILURE;
   if (waitpid(pid, &status, WUNTRACED) == pid) {
      if (!WIFEXITED(status)) {
         /* SIGTRAP is delivered to child after execve */
         if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            if (addr == 0)
               addr = find_elf_header(pid);
               printf("Found elf header: %p \n", addr);
            if (addr != 0) {
               snprintf(out_filename, sizeof(out_filename), "%s.out",
                        basename(filename));

               if (save_to_file(out_filename, pid, addr, file_size)) {
                  chmod(out_filename, 00755);
                  fprintf(stdout, "created file `%s'\n", out_filename);
                  ret_val = EXIT_SUCCESS;
               }
            }
            else {
               fprintf(stderr, "couldn't find elf header in memory\n");
            }
         }
         else {
            fprintf(stderr, "didn't receive SIGTRAP after execve\n");
         }

         /* kill child as we are finished */
         ptrace(PTRACE_KILL, pid, 0, 0);
      }
   }
   else {
      perror("waitpid");
   }

   return(ret_val);
}
