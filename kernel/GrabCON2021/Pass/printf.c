#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fdtable.h>

MODULE_LICENSE("GPL");

#ifndef __NR_PRINTF
#define __NR_PRINTF 548
#endif

char *itoa(unsigned long value, char *result, int base) {
    if (base < 2 || base > 36) { *result = '\0'; return result; }

    char* ptr = result, *ptr1 = result, tmp_char;
    unsigned long tmp_value;

    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"[35 + (tmp_value - value * base)];
    } while ( value );

    if (tmp_value < 0) *ptr++ = '-';
    *ptr-- = '\0';
    while(ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr--= *ptr1;
        *ptr1++ = tmp_char;
    }
    return result;
}

SYSCALL_DEFINE1(printf, char **, data) {
  int i, j, base_alloc_size, off_from_start, cmp_offset, add_offset, found = 0, written_chars = 0, arg_no = 1;
  long current_arg;

  char *src = data[0];
  base_alloc_size = 8;
  int len = strlen(src);
  char *dest = kmalloc(base_alloc_size, GFP_KERNEL); // allocate base buffer
  memset(dest, 0, len*2); // zero out
  char *new_string = dest;

  for(i = 0; i < len; i++) {
    cmp_offset = 0;
    add_offset = 0;
    if(*src == '%') {

      // check if there is a dollar notation in format string
      for(j = 1; j <= 9; j++) {
        if(*(src+j) == '$') {
          found = 1;
          break;
        }
        else if(*(src+j) == 'p' || *(src+j) == 'n' || *(src+j) == 'h' || *(src+j) == 's' || *(src+j) == 'c') {
          break;
        }
      }

      // if yes, get the position
      if(found) {
        char tmp[8] = {0}, *substr = strchr(src, '$');
        int len = substr - (src+1);
        strncpy(tmp, src+1, len);
        kstrtol(tmp, 10, &current_arg);
        add_offset = strlen(tmp)+1;
        cmp_offset = add_offset;

      } else {
        add_offset = 0x2;
        current_arg = arg_no;
        arg_no++;
      }

      // code for different format strings

      if(*(src+cmp_offset+0x1) == 'p') {
        char num[24] = {0};
        itoa((unsigned long)data[current_arg],num,16);
        off_from_start = dest - new_string;
        new_string = krealloc(new_string,base_alloc_size+strlen(num)+0x2, GFP_KERNEL);
        base_alloc_size += strlen(num);
        dest = new_string + off_from_start;
        strncpy(dest,"0x",2);
        strncpy(dest+2,num,strlen(num));
        dest += strlen(num)+0x2;
        src += add_offset;
        written_chars++;
      }
      else if(*(src+cmp_offset+0x1) == 'n') {
        *(unsigned int *)data[current_arg] = (unsigned int)written_chars;
        src += add_offset;
      }
      else if(*(src+cmp_offset+0x1) == 'h') {
        if(*(src+cmp_offset+0x2) == 'n') {
          *(unsigned short *)data[current_arg] = (unsigned short)written_chars;
          src += (add_offset + 0x1);
        }
        else if(*(src+cmp_offset+0x2) == 'h' && *(src+cmp_offset+0x3) == 'n') {
          *(unsigned char *)data[current_arg] = (unsigned char)written_chars;
          src += (add_offset + 0x2);
        }
      }
      else if(*(src+cmp_offset+0x1) == 's') {
        int string_len = strlen(data[current_arg]);
        off_from_start = dest - new_string;
        new_string = krealloc(new_string,base_alloc_size+string_len, GFP_KERNEL);
        base_alloc_size += string_len;
        dest = new_string + off_from_start;
        strncpy(dest,data[current_arg],strlen(data[current_arg]));
        dest += string_len;
        src += add_offset;
      }
      else if(*(src+cmp_offset+0x1) == 'c') {
        // TODO: implement actual functionality of %c
        src += 0x2;
        written_chars++;
      }
      else if(*(src+cmp_offset+0x1) >= '0' && *(src+cmp_offset+0x1) <= '9') {
        int dbg;
        long len;
        long num;
        char tmp[8] = {0};

        if(found) {
          printk(KERN_ERR "\"c\" format string cannot be used with dollar notation\n");
          kfree(new_string);
          return -1;
        }
        for(j = 0; j < 8; j++) {
          if(j >= 7) {
            printk(KERN_ERR "too long number; len = %ld\n", len);
            kfree(new_string);
            return -1;
          }
          if(*(src+0x1+j) >= '0' && *(src+0x1+j) <= '9');
          else if(*(src+0x1+j) == 'c') {
            len = j;
            break;
          }
          else {
            printk(KERN_ERR "invalid format string\n");
            kfree(new_string);
            return -1;
          }
        }
        strncpy(tmp, (src+cmp_offset+0x1), len);
        kstrtol(tmp, 10, &num);
        written_chars += num;
        src += (len + add_offset);

        // TODO: implement actual functionality of %c

      }

      src += cmp_offset;
    } else {
      off_from_start = dest - new_string;
      new_string = krealloc(new_string,++base_alloc_size, GFP_KERNEL);
      dest = new_string + off_from_start;
      *dest++ = *src++;
      written_chars++;
    }
    found = 0;
  }

  kernel_write(fdget_pos(0).file, new_string, strlen(new_string), 0); // output result
  kfree(new_string); // free buffer
  return 0;
}
