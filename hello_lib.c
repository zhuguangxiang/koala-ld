
int gval = 1;

int add(int a, int b)
{
    return a + b;
}

int hello_add(int a, int b)
{
    gval++;
    return add(a, b) + gval;
}
// gcc -shared -fPIC hello_lib.c -o libhello.so
