#ifndef SANDBOX_ENGINE_H
#define SANDBOX_ENGINE_H

#include "common.h"
#include <winnt.h>

typedef struct {
    uint8_t* decrypted_data;
    size_t decrypted_size;
    bool is_unpacked;
    char packer_type[64];
    double original_entropy;
    double decrypted_entropy;
    char core_indicators[256];
} UnpackedPayload;

// Evaluates PE binary in isolated sandbox memory simulation, decodes encryption layers (XOR/RC4/AES)
// and depacks compressed sections (UPX/Custom stubs) to extract the core raw payload for scanning.
bool sandbox_emulate_and_unpack(const uint8_t* in_data, size_t in_size, UnpackedPayload* out_payload);

// Safely releases dynamically allocated unpacked memory buffer
void free_unpacked_payload(UnpackedPayload* payload);

#endif // SANDBOX_ENGINE_H
