
#define _GNU_SOURCE
#include "elf_editor.h"
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IS_DNY(ef)  ((ef)->ehdr.e_type == ET_DYN)
#define PH_SIZE(ef) (ef)->ehdr.e_phnum
#define SH_SIZE(ef) (ef)->ehdr.e_shnum
#define ENTRY(ef)   (ef)->ehdr.e_entry

#define PAGE_SIZE   4096
#define ALIGN       (PAGE_SIZE - 1)
#define ROUND_PG(x) (((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x) ((x) & ~(ALIGN))
#define PFLAGS(x) \
    ((((x)&PF_R) ? PROT_READ : 0) | (((x)&PF_W) ? PROT_WRITE : 0) | (((x)&PF_X) ? PROT_EXEC : 0))

static int check_ehdr(Elf64_Ehdr *ehdr)
{
    unsigned char *e_ident = ehdr->e_ident;
    return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
            e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
            e_ident[EI_CLASS] != ELFCLASS64 || e_ident[EI_VERSION] != EV_CURRENT ||
            (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) || ehdr->e_phoff == 0 ||
            ehdr->e_shoff == 0 || ehdr->e_phentsize != sizeof(Elf64_Phdr) ||
            ehdr->e_shentsize != sizeof(Elf64_Shdr))
               ? 0
               : 1;
}

static void read_ehdr(Elf64FileRef ef, FILE *fp)
{
    fread(&ef->ehdr, sizeof(Elf64_Ehdr), 1, fp);
    assert(check_ehdr(&ef->ehdr));
}

static void print_phdr(Elf64FileRef ef)
{
    Elf64_Phdr *phdr;
    for (int i = 0; i < PH_SIZE(ef); i++) {
        phdr = ef->phdr + i;
        printf("[%d]: type: %d, flags: %x, virt: %lx, memsz: %lx, fileoff:%lx, filesz:%lx\n", i,
               phdr->p_type, phdr->p_flags, phdr->p_vaddr, phdr->p_memsz, phdr->p_offset,
               phdr->p_filesz);
    }
}

static void read_phdr(Elf64FileRef ef, FILE *fp)
{
    fseek(fp, ef->ehdr.e_phoff, SEEK_SET);
    int ph_sz = PH_SIZE(ef);
    ef->phdr = malloc(sizeof(Elf64_Phdr) * ph_sz);
    fread(ef->phdr, sizeof(Elf64_Phdr), ph_sz, fp);
    printf("segments: %d\n", ph_sz);
    print_phdr(ef);
}

static void print_shdr(Elf64FileRef ef)
{
    Elf64_Shdr *shdr;
    for (int i = 0; i < SH_SIZE(ef); i++) {
        shdr = ef->shdr + i;
        printf("[%d]: type: %d, flags: 0x%lx, addr: %lx, offset: %lx, size: %lx, entsize: %lx\n", i,
               shdr->sh_type, shdr->sh_flags, shdr->sh_addr, shdr->sh_offset, shdr->sh_size,
               shdr->sh_entsize);
    }
}

static void load_strtab(Elf64FileRef ef, FILE *fp)
{
    Elf64_Shdr *shdr;
    for (int i = 0; i < SH_SIZE(ef); i++) {
        shdr = ef->shdr + i;
        if (shdr->sh_type == SHT_STRTAB && shdr->sh_addr) {
            char *strtab = (char *)ef->segments[0] + shdr->sh_offset;
            // malloc(shdr->sh_size + 1);
            // fseek(fp, shdr->sh_offset, SEEK_SET);
            // fread(strtab, shdr->sh_size, 1, fp);
            ef->strlen = shdr->sh_size;
            ef->strtab = strtab;
            printf("strlen:%d\n", ef->strlen);
            printf("first str:%s\n", ef->strtab + 1);
        }
    }
}

static void print_dynsym(Elf64_Sym *dynsym, int sz, Elf64FileRef ef)
{
    Elf64_Sym *sym;
    for (int i = 0; i < sz; i++) {
        sym = dynsym + i;
        printf("[%d]: type:%d, size:%ld, ", i, ELF64_ST_TYPE(sym->st_info), sym->st_size);
        switch (ELF64_ST_TYPE(sym->st_info)) {
            case STT_FUNC:
                printf("func: %s, addr: 0x%lx\n", ef->strtab + sym->st_name, sym->st_value);
                if (!ef->func_offset) ef->func_offset = sym->st_value;
                break;
            case STT_OBJECT:
                printf("object: %s, addr: 0x%lx\n", ef->strtab + sym->st_name, sym->st_value);
                break;
            case STT_NOTYPE:
                printf("notype: %s, addr: 0x%lx\n", ef->strtab + sym->st_name, sym->st_value);
                break;
            case STT_TLS:
                printf("TLS?\n");
                break;
            default:
                break;
        }
    }
}

static void load_dynsym(Elf64FileRef ef, FILE *fp)
{
    Elf64_Sym *sym;
    Elf64_Shdr *shdr;
    for (int i = 0; i < SH_SIZE(ef); i++) {
        shdr = ef->shdr + i;
        if (shdr->sh_type == SHT_DYNSYM && shdr->sh_addr) {
            int sz = shdr->sh_size / shdr->sh_entsize;
            sym = malloc(shdr->sh_size);
            fseek(fp, shdr->sh_offset, SEEK_SET);
            fread(sym, shdr->sh_size, 1, fp);
            printf("dynsym size: %d\n", sz);
            assert(shdr->sh_entsize == sizeof(Elf64_Sym));
            print_dynsym(sym, sz, ef);
            ef->dynsym = sym;
            ef->ndyn = sz;
        }
    }
}

static void print_rela(Elf64_Rela *rela, int sz, Elf64FileRef ef)
{
    Elf64_Rela *ra;
    for (int i = 0; i < sz; i++) {
        ra = rela + i;
        printf("[%d]: offset: 0x%lx, info: 0x%lx, added: 0x%lx, type: %lx, sym: 0x%lx\n", i,
               ra->r_offset, ra->r_info, ra->r_addend, ELF64_R_TYPE(ra->r_info),
               ELF64_R_SYM(ra->r_info));
        if (ELF64_R_TYPE(ra->r_info) == R_X86_64_GLOB_DAT) {
            Elf64_Sym *sym = ef->dynsym + ELF64_R_SYM(ra->r_info);
            if (sym->st_value) {
                // .got
                Elf64_Addr *got = (Elf64_Addr *)(ef->base + ra->r_offset);
                printf("sym:%s, addr: 0x%lx, got: %p\n", ef->strtab + sym->st_name, sym->st_value,
                       got);
                *got = (Elf64_Addr)(ef->base + sym->st_value);
            }
        }

        if (ELF64_R_TYPE(ra->r_info) == R_X86_64_JUMP_SLOT) {
            Elf64_Sym *sym = ef->dynsym + ELF64_R_SYM(ra->r_info);
            if (sym->st_value) {
                // got.plt
                Elf64_Addr *got = (Elf64_Addr *)(ef->base + ra->r_offset);
                printf("sym:%s, addr: 0x%lx, got.plt: %p\n", ef->strtab + sym->st_name,
                       sym->st_value, got);
                *got = (Elf64_Addr)(ef->base + sym->st_value);
            }
        }
    }
}

static void load_rel_rela(Elf64FileRef ef, FILE *fp)
{
    Elf64_Shdr *shdr;
    for (int i = 0; i < SH_SIZE(ef); i++) {
        shdr = ef->shdr + i;
        if (shdr->sh_type == SHT_RELA && shdr->sh_addr) {
            //.rela.dyn
            Elf64_Rela *rela;
            int sz = shdr->sh_size / shdr->sh_entsize;
            rela = malloc(shdr->sh_size);
            fseek(fp, shdr->sh_offset, SEEK_SET);
            fread(rela, shdr->sh_size, 1, fp);
            printf("relocation-addend size: %d\n", sz);
            assert(shdr->sh_entsize == sizeof(Elf64_Rela));
            print_rela(rela, sz, ef);
        }
        if (shdr->sh_type == SHT_REL && shdr->sh_addr) {
            Elf64_Rel *rel;
            int sz = shdr->sh_size / shdr->sh_entsize;
            rel = malloc(shdr->sh_size);
            fseek(fp, shdr->sh_offset, SEEK_SET);
            fread(rel, shdr->sh_size, 1, fp);
            printf("relocation size: %d\n", sz);
            assert(shdr->sh_entsize == sizeof(Elf64_Rel));
        }
    }
}

static void read_shdr(Elf64FileRef ef, FILE *fp)
{
    fseek(fp, ef->ehdr.e_shoff, SEEK_SET);
    int sh_sz = SH_SIZE(ef);
    ef->shdr = malloc(sizeof(Elf64_Shdr) * sh_sz);
    fread(ef->shdr, sizeof(Elf64_Shdr), sh_sz, fp);
    printf("section: %d\n", sh_sz);
    print_shdr(ef);
}

static void load_anon(Elf64FileRef ef, FILE *fp)
{
    // calc min vaddr and max vaddr
    unsigned long min_va = (unsigned long)-1;
    unsigned long max_va = 0;
    int nsegs = 0;
    Elf64_Phdr *phdr;
    for (int i = 0; i < PH_SIZE(ef); i++) {
        phdr = ef->phdr + i;
        if (phdr->p_type != PT_LOAD && phdr->p_type != PT_TLS) continue;
        if (phdr->p_vaddr < min_va) min_va = phdr->p_vaddr;
        if (phdr->p_vaddr + phdr->p_memsz > max_va) max_va = phdr->p_vaddr + phdr->p_memsz;
        printf("min_va:0x%lx, max_va:0x%lx\n", min_va, max_va);
        ++nsegs;
    }

    min_va = TRUNC_PG(min_va);
    max_va = ROUND_PG(max_va);
    printf("min_va:0x%lx, max_va:0x%lx\n", min_va, max_va);

    /* For dynamic ELF let the kernel chose the address. */
    int dyn = IS_DNY(ef);
    unsigned char *p, *base, *hint;
    hint = dyn ? NULL : (void *)min_va;
    int flags = dyn ? 0 : MAP_FIXED;
    flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

    /* Check that we can hold the whole image. */
    printf("hint: %p\n", hint);
    base = mmap(hint, max_va - min_va, PROT_NONE, flags, -1, 0);
    assert(base != (void *)-1);
    munmap(base, max_va - min_va);

    /* Now map each segment separately in precalculated address. */
    ef->nsegs = nsegs;
    ef->segments = malloc(sizeof(void *) * nsegs);

    flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
    unsigned long off, start;
    ssize_t sz;
    int iseg = 0;
    for (int i = 0; i < PH_SIZE(ef); i++) {
        phdr = ef->phdr + i;
        if (phdr->p_type != PT_LOAD && phdr->p_type != PT_TLS) continue;
        off = phdr->p_vaddr & ALIGN;
        start = dyn ? (unsigned long)base : 0;
        start += TRUNC_PG(phdr->p_vaddr);
        sz = ROUND_PG(phdr->p_memsz + off);
        printf("segment:0x%lx, seg-size: %lx, file-size: %lx\n", start, sz, phdr->p_filesz);

        p = mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
        assert(p != (void *)-1);
        fseek(fp, phdr->p_offset, SEEK_SET);
        printf("offset:%ld\n", off);
        fread(p + off, phdr->p_filesz, 1, fp);
        mprotect(p, sz, PFLAGS(phdr->p_flags));
        ef->segments[iseg++] = p;
    }

    printf("base:%p\n", base);
    ef->base = base;

    unsigned char *entry = ENTRY(ef) + (dyn ? base : 0);
    printf("entry:%p\n", entry);

    if (dyn) {
        // void (*start)(void) = (void (*)(void))(entry);
        // start();
        // int (*call)(int, int) = (int (*)(int, int))(base + 0x10f9);
        // int res = call(100, 200);
        // printf("hello_add:%d\n", res);

    } else {
        void (*start)(void) = (void (*)(void))(entry);
        start();
    }
}

static void call_hello_add(Elf64FileRef ef)
{
    int dyn = IS_DNY(ef);
    if (dyn) {
        int (*_add_func_)(int, int) = (int (*)(int, int))(ef->base + ef->func_offset);
        int res = _add_func_(100, 200);
        printf("hello_add:%d\n", res);
        res = _add_func_(100, 200);
        printf("hello_add:%d\n", res);
        res = _add_func_(100, 200);
        printf("hello_add:%d\n", res);
    }
}

Elf64FileRef elf64_read(FILE *fp)
{
    Elf64FileRef ef = malloc(sizeof(Elf64File));
    read_ehdr(ef, fp);
    read_phdr(ef, fp);
    read_shdr(ef, fp);
    load_anon(ef, fp);
    load_strtab(ef, fp);
    load_dynsym(ef, fp);
    load_rel_rela(ef, fp);
    call_hello_add(ef);
    return ef;
}

#ifdef __cplusplus
}
#endif
