#include <stdio.h>
#include <string.h>

void test1() {
    printf("%n");                        // should flag: %n in literal
    printf("%x %x %x %x");              // should flag: multiple %x
    printf("%100$n");                    // should flag: direct param
    printf("Hello %s %s", "world");     // should flag: more specs than args
}

void test2() {
    char input[128];
    fgets(input, sizeof(input), stdin);
    printf(input);                       // should flag: tainted + no quote
}

void test3() {
    char buf[64];
    scanf("%s", buf);
    fprintf(stdout, buf);                // should flag: tainted variable as format
}

void safe() {
    char name[64];
    fgets(name, sizeof(name), stdin);
    printf("Hello %s\n", name);         // should NOT flag: literal format, variable as arg only
}
