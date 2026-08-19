#include <stdio.h>
#include <string.h>

void process_input(char *src, char *name) {
    char buf[64];
    gets(buf);
    strcpy(buf, src);
    sprintf(buf, "Name: %s", name);
}
