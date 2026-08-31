/**
 * KAVACH-ARC Controlled Demonstration Target: Use-After-Free (CWE-416)
 * 
 * Description: Buffer context is freed upon connection reset, but pointer is reused in subsequent telemetry log.
 * Test Harness: Includes trigger function for security test and normal function for regression test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t length;
    int active;
} PacketBuffer;

PacketBuffer* create_packet(const char *content) {
    if (!content) return NULL;
    PacketBuffer *pkt = (PacketBuffer*)malloc(sizeof(PacketBuffer));
    if (!pkt) return NULL;
    
    pkt->length = strlen(content);
    pkt->data = (char*)malloc(pkt->length + 1);
    if (!pkt->data) {
        free(pkt);
        return NULL;
    }
    strcpy(pkt->data, content);
    pkt->active = 1;
    return pkt;
}

void release_packet(PacketBuffer *pkt) {
    if (pkt) {
        if (pkt->data) {
            free(pkt->data);
            // VULNERABILITY: CWE-416 - Pointer not set to NULL after free
            // pkt->data = NULL;
        }
        pkt->active = 0;
    }
}

int send_telemetry(PacketBuffer *pkt) {
    if (!pkt) return -1;
    
    // VULNERABILITY: Use-After-Free access if called after release_packet
    if (pkt->data != NULL && pkt->data[0] != '\0') {
        printf("Telemetry dispatched: %s (Len: %zu)\n", pkt->data, pkt->length);
        return 0;
    }
    return -1;
}

int run_regression_test() {
    PacketBuffer *pkt = create_packet("PING_NORMAL_PACKET");
    if (!pkt) return 1;
    
    int res = send_telemetry(pkt);
    release_packet(pkt);
    free(pkt);
    
    if (res == 0) {
        printf("[REGRESSION PASS] Normal packet lifecycle completed successfully.\n");
        return 0;
    }
    return 1;
}

int run_security_test() {
    printf("[SECURITY TEST] Checking for dangling pointer dereference after packet release...\n");
    PacketBuffer *pkt = create_packet("CRITICAL_SESSION_SECRET");
    if (!pkt) return 1;
    
    release_packet(pkt);
    
    // Triggering UAF condition
    if (pkt->data != NULL) {
        printf("[SECURITY TRIGGER] Dangling pointer detected! Packet data accessed post-release.\n");
        free(pkt);
        return 2; // Vulnerability confirmed
    }
    
    free(pkt);
    printf("[SECURITY PASS] Packet data pointer safely nullified.\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--security-test") == 0) {
        return run_security_test();
    }
    if (argc > 1 && strcmp(argv[1], "--regression-test") == 0) {
        return run_regression_test();
    }
    
    printf("KAVACH-ARC Target: Use-After-Free Demo\n");
    return 0;
}
