
int gval = 1;

int add(int a, int b)
{
    return a + b;
}

int foo(int a);

int hello_add(int a, int b)
{
    gval++;
    return add(a, b) + gval + foo(a);
}
// gcc -shared -fPIC hello_lib.c -o libhello.so
// gcc -shared -fPIC hello_lib.c -o libhello.so -lfoo -L.
