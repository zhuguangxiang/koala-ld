
#ifndef _KOALA_LD_H_
#define _KOALA_LD_H_

#include <elf.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _Elf64File {
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    int nsegs;
    void **sections;
    void **segments;
    int strlen;
    char *strtab;
    char *base;
    int func_offset;
    int ndyn;
    Elf64_Sym *dynsym;
} Elf64File, *Elf64FileRef;

Elf64FileRef elf64_read(FILE *fp);

#ifdef __cplusplus
}
#endif

#endif
