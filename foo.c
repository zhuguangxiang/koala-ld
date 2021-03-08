
int foo(int a)
{
    return a + 100;
}
// gcc -shared -fPIC foo.c -o libfoo.so
