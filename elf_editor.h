
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
    // dynamic symbol
    int ndynsym;
    Elf64_Sym *dynsym;
    // dynamic link
    int ndyn;
    Elf64_Dyn *dyn;
    // dependent so
    struct _Elf64File *depend;
    Elf64_Addr *got;
    // external so
    char *ex_so;
} Elf64File, *Elf64FileRef;

Elf64FileRef elf64_read(FILE *fp);
void call_hello_add(Elf64FileRef ef);
void handle_depend(Elf64FileRef ef);

#ifdef __cplusplus
}
#endif

#endif
