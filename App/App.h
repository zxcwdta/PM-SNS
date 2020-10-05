/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <iostream>
#include "../Globals.hpp"
#include "../CONFIG.h"
#include "../CONFIG_FLAGS.h"
#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#if   defined(__GNUC__)
# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"
#endif

extern sgx_enclave_id_t global_eid;    /* global enclave id */
#if defined(__cplusplus)
extern "C" {
#endif

void ecall_libcxx_functions(void);
void ecall_libcxx_sys_init(void);
void ecall_libcxx_sys_reg(int*);

void ecall_libcxx_sys_search_token_computation(char *serialised_profile, size_t profile_len, char *token_out, size_t out_len, char *secret_out, size_t secret_len, int uid);
void ecall_libcxx_encrypt(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, int userId);
void ecall_libcxx_decrypt(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, int uid);
void ecall_libcxx_decrypt_with_key(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, char *key, size_t key_len);
void ecall_libcxx_encrypt_with_key(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, char *key, size_t key_len);
#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
