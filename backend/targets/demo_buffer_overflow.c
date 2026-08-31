/**
 * KAVACH-ARC Controlled Demonstration Target: Buffer Overflow (CWE-120 / CWE-787)
 * 
 * Description: Vulnerable user token parser copying unbounded input into a fixed-size stack buffer.
 * Test Harness: Includes trigger function for security test and normal function for regression test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TOKEN_LEN 32

typedef struct {
    char token[MAX_TOKEN_LEN];
    int is_admin;
} UserSession;

// Vulnerable function: uses strcpy without bounds checking
int process_auth_token(const char *input_raw, UserSession *session) {
    if (!input_raw || !session) {
        return -1;
    }
    
    session->is_admin = 0;
    
    // VULNERABILITY: CWE-120 - Unbounded string copy
    strcpy(session->token, input_raw);
    
    // Check if token contains admin prefix
    if (strncmp(session->token, "ADM-", 4) == 0) {
        session->is_admin = 1;
    }
    
    return 0;
}

int run_regression_test() {
    UserSession s;
    const char *valid_input = "USER-12345";
    if (process_auth_token(valid_input, &s) == 0 && s.is_admin == 0 && strcmp(s.token, "USER-12345") == 0) {
        printf("[REGRESSION PASS] Normal authentication token processed correctly.\n");
        return 0;
    }
    printf("[REGRESSION FAIL] Normal authentication token failed.\n");
    return 1;
}

int run_security_test() {
    UserSession s;
    // Malicious payload exceeding 32 bytes to trigger buffer overflow
    const char *exploit_payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_OVERFLOW";
    printf("[SECURITY TEST] Executing boundary check with 55-byte input on 32-byte buffer...\n");
    
    process_auth_token(exploit_payload, &s);
    
    if (s.is_admin != 0) {
        printf("[SECURITY TRIGGER] Buffer overflow corrupted adjacent memory struct!\n");
        return 2; // Vulnerability confirmed
    }
    
    printf("[SECURITY PASS] Input handled safely without memory corruption.\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--security-test") == 0) {
        return run_security_test();
    }
    if (argc > 1 && strcmp(argv[1], "--regression-test") == 0) {
        return run_regression_test();
    }
    
    printf("KAVACH-ARC Target: Buffer Overflow Demo\n");
    printf("Usage: %s [--security-test | --regression-test]\n", argv[0]);
    return 0;
}
