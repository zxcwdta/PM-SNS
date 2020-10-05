/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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


#include <cstdlib>
#include <string.h>
//#include <stdio.h>
#include <math.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "../Enclave.h"
#include "user_types.h"
#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <map>
#include <unordered_map>
#include <string>
#define DEBUG_PRINT 1
#define KEY_SIZE 16
#define BUFLEN 2048
#define PROFILE_SIZE 140
#define NUM_ELEMENTS_PROFILE 4
#define PROFILE_OFFSET 68
User* profile_deserialisation(char*);
static int p_size[NUM_ELEMENTS_PROFILE] = { 4, 1, 32, 32 };
enum PROFILE_ELEMENT{ PROFILE_AGE = 0, PROFILE_GENDER, PROFILE_LOCATION, PROFILE_HOBBY };
typedef struct keywrapper {
	sgx_aes_gcm_128bit_key_t key;
}key_wrapper;
typedef struct pair {
	char STA[33];
	char STB[33];
}search_token_pair;
typedef struct sec_pair {
	char CA[65];
	char *CB;
}secret_pair;
// Key Table consists of user id and its corresponding symmetric key
std::unordered_map<int, key_wrapper> KT;
std::unordered_map<std::string, int> IM;
// Keep track of the number of registered users in SGX
int counter;
sgx_aes_gcm_128bit_key_t enclave_key = { 0x44, 0x54, 0x61, 0x5f, 0x49, 0x49, 0x44, 0x58, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
void ecall_sys_init()
{
	counter = 1234;
}

void ecall_sys_reg(int *uid)
{
	// initialise a key and assign random values to it.
	sgx_aes_gcm_128bit_key_t key;
	sgx_read_rand(key, KEY_SIZE);
	key_wrapper wrapper = { { 0 } };
	memcpy(wrapper.key, key, KEY_SIZE);
	// assign a user id to the key generated above and store them into KT.
	KT.insert(std::pair<int, key_wrapper>(counter, wrapper));

	#ifdef DEBUG_PRINT
	printf("\nreg successful, uid: %d, key beofre into KT: ", counter);
	for (int i = 0; i < KEY_SIZE; i++)
		printf("%x ", (unsigned char)key[i]);
	printf("\n");
	printf("\nreg successful, uid: %d, key retrieved from KT: ", counter);
	for (int i = 0; i < KEY_SIZE; i++)
		printf("%x ", (unsigned char)KT.find(counter)->second.key[i]);
	printf("\n");
	#endif
	*uid = counter;
	counter++;
}

void ecall_encrypt(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, int userId)

{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);
	sgx_aes_gcm_128bit_key_t key = { 0 };
	memcpy(key, KT.find(userId)->second.key, KEY_SIZE);
	#ifdef DEBUG_PRINT
//	printf("ecall_encrypt:: uid: %d, key: ", userId);
//	for (int i = 0; i < 16; i++)
//		printf("%x ", (unsigned char)key[i]);
//	printf("\n");
	#endif
	sgx_rijndael128GCM_encrypt(
		&key,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	memcpy(encMessageOut,p_dst,lenOut);
}
void ecall_encrypt_with_key(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, char *key, size_t key_len)

{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);
	#ifdef DEBUG_PRINT
//	printf("ecall_encrypt:: uid: %d, key: ", userId);
//	for (int i = 0; i < 16; i++)
//		printf("%x ", (unsigned char)key[i]);
//	printf("\n");
	#endif
	sgx_rijndael128GCM_encrypt(
		(sgx_aes_gcm_128bit_key_t *)key,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	memcpy(encMessageOut,p_dst,lenOut);
}

void ecall_decrypt(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, int userId)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};
	sgx_aes_gcm_128bit_key_t key = { 0 };
	memcpy(key, KT.find(userId)->second.key, KEY_SIZE);
	#ifdef DEBUG_PRINT
//	printf("ecall_decrypt:: uid: %d, key: ", userId);
//	for (int i = 0; i < 16; i++)
//		printf("%x ", (unsigned char)key[i]);
//	printf("\n");
	#endif
	sgx_rijndael128GCM_decrypt(
		&key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);
	memcpy(decMessageOut, p_dst, lenOut);
}

void ecall_decrypt_with_key(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, char *key, size_t key_len)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};
	#ifdef DEBUG_PRINT
//	printf("ecall_decrypt:: uid: %d, key: ", userId);
//	for (int i = 0; i < 16; i++)
//		printf("%x ", (unsigned char)key[i]);
//	printf("\n");
	#endif
	sgx_rijndael128GCM_decrypt(
		(sgx_aes_gcm_128bit_key_t *)key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);
	memcpy(decMessageOut, p_dst, lenOut);
}

User* profile_deserialisation(char *dec_profile)
{
	int cnt = 0;
	User *profile = (User*)malloc(PROFILE_SIZE);
	memcpy(&profile->uid, dec_profile+cnt, 4);
	cnt += 4;
	memcpy(profile->fname, dec_profile+cnt, 32); 	
	cnt += 32;
	memcpy(profile->lname, dec_profile+cnt, 32); 	
	cnt += 32;
	memcpy(&profile->age, dec_profile+cnt, 4);
	cnt += 4;
	memcpy(&profile->gender, dec_profile+cnt, 1);
	cnt += 1;
	memcpy(profile->location, dec_profile+cnt, 32);
	cnt += 32;
	memcpy(profile->hobby, dec_profile+cnt, 32);
	return profile;
}

char itob(uint8_t val)
{
	switch(val)
	{
		case(0): return '0';
		case(1): return '1';
		case(2): return '2';
		case(3): return '3';
		case(4): return '4';
		case(5): return '5';
		case(6): return '6';
		case(7): return '7';
		case(8): return '8';
		case(9): return '9';
		case(10): return 'A';
		case(11): return 'B';
		case(12): return 'C';
		case(13): return 'D';
		case(14): return 'E';
		case(15): return 'F';
	}
}
unsigned char* sha256(char *string, char outputBuffer[65], unsigned char *rst_raw)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
	for (int i = 0; i < SHA256_DIGEST_LENGTH ; i++)
	{
		uint8_t h, l;
		h = hash[i] >> 4; 
		l = hash[i] & 0x0F; 
		outputBuffer[i * 2] = itob(h);
		outputBuffer[i * 2 + 1] = itob(l);
	}
	outputBuffer[64] = {'\0'};
	#ifdef DEBUG_PRINT
	printf("ecall_sha256:: %s -> %s\n", string, outputBuffer);
	#endif
	memcpy(rst_raw, hash, 32);
}

void itoc(char *src, int n)
{
	char bytes[4] = { 0 };
	bytes[0] = (n >> 24) & 0xFF;
	bytes[1] = (n >> 16) & 0xFF;
	bytes[2] = (n >> 8) & 0xFF;
	bytes[3] = n & 0xFF;
	memcpy(src, bytes, 4);
}

char *get_attribute(User *profile, int pos)
{
	switch (pos)
	{
		case (PROFILE_AGE): return (char*)&(profile->age); 
		case (PROFILE_GENDER): return (char*)&(profile->gender);
		case (PROFILE_LOCATION): return profile->location;
		case (PROFILE_HOBBY): return profile->hobby;
	}
}
void ecall_sys_search_token_computation(char *serialised_profile, size_t profile_len, char *token_out, size_t out_len, char *secret_out, size_t secret_len, int uid)
{
	// First is to decrypt the profile using the key assigned to uid.
	// Given the size of a profile is fixed, we initialise a continuous memory space
	// for storing decrypted result.	
	char *dec_profile = (char*)malloc(PROFILE_SIZE);
	ecall_decrypt(serialised_profile, profile_len, dec_profile, PROFILE_SIZE, uid);
	printf("ecall_sys_search_token_computation:: ");
	for (int i = 0; i < PROFILE_SIZE; i++)
		printf("%c ", dec_profile[i]);	
	printf("\n");
	// deserialise the profile
	User *profile = profile_deserialisation(dec_profile);
	#ifdef DEBUG_PRINT
	printf("ecall_sys_search_token_computation:: uid: %d, fname = %s, lname = %s, age = %d, gender = %d, location = %s, hobby = %s\n",
	profile->uid, profile->fname, profile->lname, profile->age, profile->gender, profile->location, profile->hobby);
	#endif
	
	int token_out_offset = 0;
	int secret_out_offset = 0;
	for (int i = 0; i < NUM_ELEMENTS_PROFILE; i++)
	{
	char sha256_buffer[65] = { 0 };
	// Start to compute search token for an attribute
	char *digest_buffer = (char*)malloc(16 + p_size[i]);
	memcpy(digest_buffer, enclave_key, 16);
	memcpy(digest_buffer+16, get_attribute(profile, i), p_size[i]);
	unsigned char *stab_rst_raw = (unsigned char*)malloc(32);
	sha256(digest_buffer, sha256_buffer, stab_rst_raw);	
	
	// Trying to find the index for such search token computed above
	search_token_pair pair = { {0}, {0} };
	memcpy(pair.STA, sha256_buffer, 32);
	pair.STA[32] = {'\0'};
	memcpy(pair.STB, sha256_buffer+32, 32);
	pair.STB[32] = {'\0'};
	std::string sta_str( pair.STA );
//	printf("std:: struct: %s, string: %s\n", pair.STA, sta_str.c_str());
	auto result = IM.find(sta_str);
	if (result == IM.end())
	{
		printf("%s does not exist, initialise it.\n", sta_str.c_str());
		int cnt = 0;
		IM.insert(std::pair<std::string, int>(sta_str, cnt));
		secret_pair secret = {{0}};	
		char *ca_plain_digest_buffer = (char*)malloc(36);
		memcpy(ca_plain_digest_buffer, pair.STA, 32);
		memcpy(ca_plain_digest_buffer+32, &cnt, 4);
		char c1[65] = { 0 };
		unsigned char *c1_raw = (unsigned char*)malloc(32);
		sha256(ca_plain_digest_buffer, c1, c1_raw);	
		memcpy(secret.CA, c1, 64);
		
		printf("STA: %s\nSTB: %s\n", pair.STA, pair.STB);
		
		size_t cb_len = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + 4);
		secret.CB = (char*)malloc(cb_len);
		char *uid_ptr = (char*)malloc(4);
		itoc(uid_ptr, uid);
		ecall_encrypt_with_key(uid_ptr, 4, secret.CB, cb_len, (char*)stab_rst_raw+16, 16);
		// to serialise the search token and secret token
		

		memcpy(token_out+token_out_offset, pair.STA, 32);
		token_out_offset += 32;
		memcpy(token_out+token_out_offset, stab_rst_raw+16, 16);
		token_out_offset += 16;
		// CA, CB
		memcpy(secret_out+secret_out_offset, secret.CA, 64);
		secret_out_offset += 64;
		memcpy(secret_out+secret_out_offset, secret.CB, cb_len);
		secret_out_offset += cb_len;
	}
	else
	{
		printf("%s found, adding 1 on top.\n", sta_str.c_str());
		result->second += 1;
	}
	}
}
