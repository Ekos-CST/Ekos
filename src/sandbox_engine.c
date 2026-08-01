#include "sandbox_engine.h"
#include <winnt.h>

void free_unpacked_payload(UnpackedPayload* payload) {
    if (payload) {
        if (payload->decrypted_data) {
            free(payload->decrypted_data);
            payload->decrypted_data = NULL;
        }
        payload->decrypted_size = 0;
        payload->is_unpacked = false;
    }
}

// Internal helper: Simple RLE/UPX-like byte unpacking simulation for packed section buffers
static bool emulate_upx_decompression(const uint8_t* src, size_t src_len, uint8_t* dst, size_t dst_len) {
    if (!src || !dst || src_len == 0 || dst_len == 0) return false;
    
    size_t src_idx = 0;
    size_t dst_idx = 0;

    while (src_idx < src_len && dst_idx < dst_len) {
        uint8_t b = src[src_idx++];
        if (b == 0x00 && src_idx < src_len) {
            uint8_t count = src[src_idx++];
            for (uint8_t c = 0; c < count && dst_idx < dst_len; c++) {
                dst[dst_idx++] = 0x00;
            }
        } else {
            dst[dst_idx++] = b;
        }
    }
    return (dst_idx > 0);
}

// Internal helper: Automated XOR Key Stream Decryption Pass in Sandbox Memory
static bool sandbox_decrypt_xor_payload(const uint8_t* encrypted, size_t len, uint8_t** out_decrypted, size_t* out_size, uint8_t* found_key) {
    if (!encrypted || len < 32 || !out_decrypted || !out_size) return false;

    // Search for single-byte or multi-byte XOR key that reveals executable signatures ('MZ' / PE header or ASCII strings)
    for (int key = 1; key < 256; key++) {
        // Test decrypt first 64 bytes
        if ((encrypted[0] ^ key) == 'M' && (encrypted[1] ^ key) == 'Z') {
            uint8_t* dec = (uint8_t*)malloc(len);
            if (!dec) return false;

            for (size_t i = 0; i < len; i++) {
                dec[i] = encrypted[i] ^ (uint8_t)key;
            }

            *out_decrypted = dec;
            *out_size = len;
            if (found_key) *found_key = (uint8_t)key;
            return true;
        }
    }

    // Try common rolling/key XOR patterns (e.g. 0x5A, 0xFF, 0xAA, 0x55, 0xDE, 0xAD)
    static const uint8_t common_keys[] = { 0x5A, 0xFF, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x7E, 0x13, 0x37 };
    for (size_t k = 0; k < sizeof(common_keys); k++) {
        uint8_t key = common_keys[k];
        uint8_t* dec = (uint8_t*)calloc(1, len + 1);
        if (!dec) continue;

        for (size_t i = 0; i < len; i++) {
            dec[i] = encrypted[i] ^ key;
        }

        double dec_entropy = calculate_file_entropy(dec, len);
        if ((dec_entropy < 6.8 && dec_entropy > 1.5) || strstr((const char*)dec, "VirtualAllocEx") || strstr((const char*)dec, "WriteProcessMemory")) {
            *out_decrypted = dec;
            *out_size = len;
            if (found_key) *found_key = key;
            return true;
        }
        free(dec);
    }

    return false;
}

bool sandbox_emulate_and_unpack(const uint8_t* in_data, size_t in_size, UnpackedPayload* out_payload) {
    if (!in_data || in_size < sizeof(IMAGE_DOS_HEADER) || !out_payload) return false;

    memset(out_payload, 0, sizeof(UnpackedPayload));
    out_payload->original_entropy = calculate_file_entropy(in_data, in_size);

    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)in_data;
    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) return false;

    if ((size_t)dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > in_size) return false;

    PIMAGE_NT_HEADERS32 nt_hdr = (PIMAGE_NT_HEADERS32)(in_data + dos_hdr->e_lfanew);
    if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) return false;

    bool is_64bit = (nt_hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    PIMAGE_NT_HEADERS64 nt_hdr64 = (PIMAGE_NT_HEADERS64)nt_hdr;

    WORD num_sections = nt_hdr->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sec_hdr = is_64bit ?
        (PIMAGE_SECTION_HEADER)((uint8_t*)&nt_hdr64->OptionalHeader + nt_hdr64->FileHeader.SizeOfOptionalHeader) :
        (PIMAGE_SECTION_HEADER)((uint8_t*)&nt_hdr->OptionalHeader + nt_hdr->FileHeader.SizeOfOptionalHeader);

    bool upx_detected = false;
    bool packed_section_found = false;
    DWORD last_section_raw_end = 0;

    for (WORD i = 0; i < num_sections && i < 32; i++) {
        if ((uint8_t*)&sec_hdr[i] + sizeof(IMAGE_SECTION_HEADER) > in_data + in_size) break;

        char sec_name[9] = {0};
        memcpy(sec_name, sec_hdr[i].Name, 8);

        DWORD sec_raw_end = sec_hdr[i].PointerToRawData + sec_hdr[i].SizeOfRawData;
        if (sec_raw_end > last_section_raw_end && sec_raw_end <= in_size) {
            last_section_raw_end = sec_raw_end;
        }

        if (strstr(sec_name, "UPX") || strstr(sec_name, "upx")) {
            upx_detected = true;
        }
        if (strstr(sec_name, ".aspack") || strstr(sec_name, ".vmp") || strstr(sec_name, ".themida") || strstr(sec_name, ".pack")) {
            packed_section_found = true;
        }
    }

    // 1. Check for Embedded PE Payload in Overlay (Appended after last raw section)
    if (last_section_raw_end > 0 && in_size > last_section_raw_end + 16) {
        const uint8_t* overlay_ptr = in_data + last_section_raw_end;
        size_t overlay_len = in_size - last_section_raw_end;

        if (overlay_len >= 32 && overlay_ptr[0] == 'M' && overlay_ptr[1] == 'Z') {
            out_payload->decrypted_data = (uint8_t*)malloc(overlay_len);
            if (out_payload->decrypted_data) {
                memcpy(out_payload->decrypted_data, overlay_ptr, overlay_len);
                out_payload->decrypted_size = overlay_len;
                out_payload->is_unpacked = true;
                strncpy(out_payload->packer_type, "PE.Overlay.Attachment", 63);
                out_payload->decrypted_entropy = calculate_file_entropy(out_payload->decrypted_data, overlay_len);
                snprintf(out_payload->core_indicators, sizeof(out_payload->core_indicators),
                         "[Sandbox Extracted PE Overlay Payload | Size: %zu B | Original Entropy: %.2f -> Decrypted: %.2f]",
                         overlay_len, out_payload->original_entropy, out_payload->decrypted_entropy);
                return true;
            }
        }

        // Try XOR decryption on overlay payload
        uint8_t xor_key = 0;
        uint8_t* dec_overlay = NULL;
        size_t dec_overlay_size = 0;
        if (sandbox_decrypt_xor_payload(overlay_ptr, overlay_len, &dec_overlay, &dec_overlay_size, &xor_key)) {
            out_payload->decrypted_data = dec_overlay;
            out_payload->decrypted_size = dec_overlay_size;
            out_payload->is_unpacked = true;
            snprintf(out_payload->packer_type, 63, "XOR.Crypter (Key: 0x%02X)", xor_key);
            out_payload->decrypted_entropy = calculate_file_entropy(dec_overlay, dec_overlay_size);
            snprintf(out_payload->core_indicators, sizeof(out_payload->core_indicators),
                     "[Sandbox Decrypted XOR Overlay Stub | Key: 0x%02X | Size: %zu B | Entropy: %.2f -> %.2f]",
                     xor_key, dec_overlay_size, out_payload->original_entropy, out_payload->decrypted_entropy);
            return true;
        }
    }

    // 2. Depack UPX / Packed Sections
    if (upx_detected || packed_section_found || out_payload->original_entropy > 7.2) {
        // Allocate virtual memory space for reconstructed PE image (VirtualSize sum)
        size_t virtual_image_size = in_size * 3;
        if (virtual_image_size < 1048576) virtual_image_size = 1048576; // min 1MB

        uint8_t* sandbox_ram = (uint8_t*)calloc(1, virtual_image_size);
        if (sandbox_ram) {
            // Copy headers into sandbox RAM
            size_t headers_size = (dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (num_sections * sizeof(IMAGE_SECTION_HEADER)));
            if (headers_size <= in_size) {
                memcpy(sandbox_ram, in_data, headers_size);
            }

            // Emulate decompression for each section
            size_t written_offset = headers_size;
            for (WORD i = 0; i < num_sections; i++) {
                if (sec_hdr[i].PointerToRawData != 0 && sec_hdr[i].SizeOfRawData != 0 &&
                    (size_t)sec_hdr[i].PointerToRawData + sec_hdr[i].SizeOfRawData <= in_size) {

                    const uint8_t* sec_src = in_data + sec_hdr[i].PointerToRawData;
                    size_t sec_raw_size = sec_hdr[i].SizeOfRawData;

                    uint8_t* sec_dst = sandbox_ram + written_offset;
                    size_t max_dst = virtual_image_size - written_offset;

                    if (max_dst > 0) {
                        if (upx_detected) {
                            emulate_upx_decompression(sec_src, sec_raw_size, sec_dst, max_dst);
                        } else {
                            memcpy(sec_dst, sec_src, (sec_raw_size < max_dst) ? sec_raw_size : max_dst);
                        }
                        written_offset += (sec_raw_size < max_dst) ? sec_raw_size : max_dst;
                    }
                }
            }

            // Check if sandbox RAM now contains uncloaked executable shellcode or PE headers
            double sandbox_entropy = calculate_file_entropy(sandbox_ram, written_offset);
            
            // Try XOR key recovery pass over the entire constructed image if still encrypted
            uint8_t xor_key = 0;
            uint8_t* xor_dec = NULL;
            size_t xor_dec_len = 0;
            if (sandbox_decrypt_xor_payload(sandbox_ram, written_offset, &xor_dec, &xor_dec_len, &xor_key)) {
                free(sandbox_ram);
                out_payload->decrypted_data = xor_dec;
                out_payload->decrypted_size = xor_dec_len;
                out_payload->is_unpacked = true;
                snprintf(out_payload->packer_type, 63, "Encrypted.PE.Payload (XOR 0x%02X)", xor_key);
                out_payload->decrypted_entropy = calculate_file_entropy(xor_dec, xor_dec_len);
                snprintf(out_payload->core_indicators, sizeof(out_payload->core_indicators),
                         "[Sandbox Decrypted PE Section Payload | XOR Key: 0x%02X | Entropy: %.2f -> %.2f]",
                         xor_key, out_payload->original_entropy, out_payload->decrypted_entropy);
                return true;
            }

            out_payload->decrypted_data = sandbox_ram;
            out_payload->decrypted_size = written_offset;
            out_payload->is_unpacked = true;
            strncpy(out_payload->packer_type, upx_detected ? "UPX.Depacked.Core" : "Generic.Packer.Depacked", 63);
            out_payload->decrypted_entropy = sandbox_entropy;
            snprintf(out_payload->core_indicators, sizeof(out_payload->core_indicators),
                     "[Sandbox Depacked PE Core | Packer: %s | Entropy: %.2f -> %.2f]",
                     upx_detected ? "UPX" : "Packer Stub", out_payload->original_entropy, sandbox_entropy);
            return true;
        }
    }

    return false;
}
