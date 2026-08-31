#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 16

void process_input(const char *input) {
    char buffer[BUFFER_SIZE];

    // Deliberately vulnerable: unbounded copy
    strcpy(buffer, input);

    printf("Processed input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: test_upload <input>\n");
        return 1;
    }

    process_input(argv[1]);

    return 0;
}