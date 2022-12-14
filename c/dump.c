#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

void dump(uint64_t x)
{ // https://godbolt.org/
    char buf[32];
    size_t buf_sz = 1;
    buf[sizeof(buf) - buf_sz] = '\n';
    do {
        buf[sizeof(buf) - buf_sz -1] = x % 10 + '0';
        buf_sz++;
        x /= 10;
    } while (x);

    write(1, &buf[sizeof(buf) - buf_sz], buf_sz);
}

int main()
{
    dump(69420);
    dump(0);
    return 0;
}
