import struct, os

def create_sample():
    os.makedirs('test_samples', exist_ok=True)
    out_path = 'test_samples/packed_malware_sample.exe'
    
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 60, 64)
    
    nt_headers = bytearray(24)
    nt_headers[0:4] = b'PE\x00\x00'
    struct.pack_into('<H', nt_headers, 4, 0x014c) # 32-bit Machine
    struct.pack_into('<H', nt_headers, 6, 1) # 1 section
    struct.pack_into('<H', nt_headers, 20, 96) # SizeOfOptionalHeader = 96 at offset 20 (4+16)
    
    opt_header = bytearray(96)
    struct.pack_into('<H', opt_header, 0, 0x010b) # PE32
    
    sec_header = bytearray(40)
    sec_header[0:5] = b'.text'
    struct.pack_into('<I', sec_header, 16, 512)
    struct.pack_into('<I', sec_header, 20, 512)
    struct.pack_into('<I', sec_header, 36, 0x60000020)
    
    header_size = 64 + 24 + 96 + 40
    padding = bytearray(512 - header_size)
    dummy_code = b'\x90' * 512
    
    raw_shellcode = b"\x90" * 32 + b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
    key = 0x5A
    encrypted_overlay = bytes([b ^ key for b in raw_shellcode])
    
    pe_file = dos_header + nt_headers + opt_header + sec_header + padding + dummy_code + encrypted_overlay
    
    with open(out_path, 'wb') as f:
        f.write(pe_file)
    print(f"Created: {out_path}")

if __name__ == '__main__':
    create_sample()
