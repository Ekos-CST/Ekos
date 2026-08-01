#ifndef CERT_VERIFIER_H
#define CERT_VERIFIER_H

#include "common.h"

bool verify_file_digital_signature(const wchar_t* w_file_path);
bool is_certified_system_file(const char* file_path);
bool is_ekos_licensed_file(const char* file_path);

#endif // CERT_VERIFIER_H
