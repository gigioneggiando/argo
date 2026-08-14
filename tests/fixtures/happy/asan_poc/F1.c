#include <stdlib.h>

int main(void) {
    char *buf = malloc(10);
    buf[10] = 'A';  /* heap-buffer-overflow: classic off-by-one write, ASan catches this */
    free(buf);
    return 0;
}
