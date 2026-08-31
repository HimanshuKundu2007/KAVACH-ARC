/**
 * KAVACH-ARC Controlled Demonstration Target: Integer Overflow & Memory Wrap (CWE-190)
 * 
 * Description: Unchecked arithmetic in buffer size calculation causes integer overflow and heap underallocation.
 * Test Harness: Includes trigger function for security test and normal function for regression test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned int element_count;
    unsigned int element_size;
    char *buffer;
} VectorTable;

VectorTable* allocate_vector(unsigned int count, unsigned int size) {
    VectorTable *vec = (VectorTable*)malloc(sizeof(VectorTable));
    if (!vec) return NULL;
    
    vec->element_count = count;
    vec->element_size = size;
    
    // VULNERABILITY: CWE-190 - Unchecked multiplication leads to integer overflow wrap-around
    unsigned int total_bytes = count * size;
    
    vec->buffer = (char*)malloc(total_bytes);
    if (!vec->buffer) {
        free(vec);
        return NULL;
    }
    
    memset(vec->buffer, 0, total_bytes);
    return vec;
}

void free_vector(VectorTable *vec) {
    if (vec) {
        if (vec->buffer) free(vec->buffer);
        free(vec);
    }
}

int run_regression_test() {
    VectorTable *v = allocate_vector(10, 4); // 40 bytes
    if (v && v->buffer) {
        printf("[REGRESSION PASS] Normal vector allocation of 40 bytes succeeded.\n");
        free_vector(v);
        return 0;
    }
    return 1;
}

int run_security_test() {
    printf("[SECURITY TEST] Checking integer overflow guard for large vector allocation...\n");
    // Large counts that wrap 32-bit unsigned int
    unsigned int large_count = 1073741825; // 0x40000001
    unsigned int elem_size = 4;            // Product is 4 (wraps 2^32)
    
    // Check if system checks for overflow before malloc
    if ((unsigned long long)large_count * elem_size > 0xFFFFFFFFULL) {
        // Without patch in allocate_vector, it computes count * size = 4
        VectorTable *v = allocate_vector(large_count, elem_size);
        if (v && v->buffer) {
            printf("[SECURITY TRIGGER] Underallocated buffer due to integer overflow! Allocated 4 bytes instead of 4GB.\n");
            free_vector(v);
            return 2;
        }
    }
    
    printf("[SECURITY PASS] Integer overflow prevented.\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--security-test") == 0) {
        return run_security_test();
    }
    if (argc > 1 && strcmp(argv[1], "--regression-test") == 0) {
        return run_regression_test();
    }
    
    printf("KAVACH-ARC Target: Integer Overflow Demo\n");
    return 0;
}
