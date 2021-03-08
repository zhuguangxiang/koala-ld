
#include "elf_editor.h"

int main()
{
    char *file = "./libhello.so";
    // char *file = "./hello_exe";
    FILE *fp = fopen(file, "r");
    Elf64FileRef efp = elf64_read(fp);
    handle_depend(efp);
    call_hello_add(efp);
    return 0;
}
