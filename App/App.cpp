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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include "utils.hpp"
#include <iostream>
#include <unistd.h>
#include <pwd.h>
#include <map>
#include <unordered_map>
#include <string>
#define MAX_PATH FILENAME_MAX
#include "sgx_urts.h"
#include "LocalStorage.hpp"
#include "App.h"
#include "Enclave_u.h"
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <openssl/sha.h>
#define MAX_PATH FILENAME_MAX
#define CIRCUIT_ORAM
#define NUMBER_OF_WARMUP_REQUESTS 0
#define ANALYSIS 1
#define MILLION 1E6
#define HASH_LENGTH 32


#ifdef DETAILED_MICROBENCHMARKER
  typedef struct detailed_microbenchmark_params{
    uint8_t oram_type;  
    uint8_t recursion_levels;
    uint32_t num_requests;
    bool on;
  }det_mb_params;

  det_mb_params DET_MB_PARAMS;
  det_mb ***MB = NULL; 
  uint32_t req_counter=0;
#endif

//#define NO_CACHING_APP 1
//#define EXITLESS_MODE 1
//#define POSMAP_EXPERIMENT 1
char *pid;
char *pid_msg;
size_t pidLen;

// Global Variables Declarations
uint64_t PATH_SIZE_LIMIT = 1 * 1024 * 1024;
uint32_t aes_key_size = 16;
uint32_t hash_size = 32;	
#define ADDITIONAL_METADATA_SIZE 24
uint32_t oram_id = 0;

//Timing variables
uint32_t recursion_levels_e = 0;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
bool resume_experiment = false;
bool inmem_flag = true;

// Storage Backends:
//TODO: Switch to LS for each LSORAM, Path, Circuit
LocalStorage ls;
std::map<uint32_t, LocalStorage*> ls_PORAM;
std::map<uint32_t, LocalStorage*> ls_CORAM;
std::map<uint32_t, std::vector<tuple*>*> ls_LSORAM;


// double compute_stddev(double *elements, uint32_t num_elements) {
//   double mean = 0, var = 0, stddev;
//   for(uint32_t i=0; i<num_elements; i++) {
//     mean+=elements[i];   
//   }
//   mean=(mean/num_elements);
//   for(uint32_t i=0; i<num_elements; i++) {
//     double diff = mean - elements[i];
//     var+=(diff*diff);
//   }
//   var=var/num_elements;
//   stddev = sqrt(var);
//   return stddev;
// }

// double compute_avg(double *elements, uint32_t num_elements) {
//   double mean = 0, var = 0, stddev;
//   for(uint32_t i=0; i<num_elements; i++) {
//     mean+=elements[i];   
//   }
//   mean=(mean/num_elements);
//   return mean;
// }

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

struct oram_request{
  uint32_t *id;
  uint32_t *level;
  uint32_t *d_lev;
  bool *recursion;
  bool *block;
};

struct oram_response{
  unsigned char *path;
  unsigned char *path_hash;
  unsigned char *new_path;
  unsigned char *new_path_hash;
};

struct thread_data{
  struct oram_request *req;
  struct oram_response *resp;
};

struct thread_data td;
struct oram_request req_struct;
struct oram_response resp_struct;	
unsigned char *data_in;
unsigned char *data_out;



EC_KEY *ENCLAVE_PUBLIC_KEY = NULL;
unsigned char *enclave_public_key;

uint32_t NUM_EXPECTED_PARAMS = 12;
bool RESUME_EXPERIMENT;
uint32_t DATA_SIZE;
uint32_t MAX_BLOCKS;
int REQUEST_LENGTH;
uint32_t STASH_SIZE;
uint32_t OBLIVIOUS_FLAG = 0;
uint32_t RECURSION_DATA_SIZE = 0;
uint32_t ORAM_TYPE = 0;

unsigned char *encrypted_request, *tag_in, *encrypted_response, *tag_out;
uint32_t request_size, response_size;
// unsigned char *data_in;
// unsigned char *data_out;
uint32_t bulk_batch_size=0;

int64_t currentTimeMillis(); 
int64_t currentTimeMicro(); 
uint32_t getRandomId();
clock_t generate_request_start, generate_request_stop, extract_response_start, extract_response_stop, process_request_start, process_request_stop, generate_request_time, extract_response_time,  process_request_time;
uint8_t Z;
FILE *iquery_file; 
std::string log_file;


int64_t currentTimeMillis() {
  struct timeval time;
  gettimeofday(&time, NULL);
  int64_t s1 = (int64_t)(time.tv_sec) * 1000;
  int64_t s2 = (time.tv_usec / 1000);
  return s1 + s2;
}

int64_t currentTimeMicro() {
  struct timeval time;
  gettimeofday(&time, NULL);
  int64_t s1 = (int64_t)(time.tv_sec) * 1000000;
  int64_t s2 = (time.tv_usec);
  return s1 + s2;
}

uint32_t getRandomId()
{
 	int x = 0;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;
	return (uint32_t)x;
}
/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */

int initialize_enclave(void) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        fprintf(stderr, "ZT_LSORAM:Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            fprintf(stderr, "ZT_LSORAM:Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        fprintf(stderr, "Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

// int initialize_enclave()
// {
//     sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
//     /* Call sgx_create_enclave to initialize an enclave instance */
//     /* Debug Support: set 2nd parameter to 1 */
//     ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
//     if (ret != SGX_SUCCESS) {
//         print_error_message(ret);
//         return -1;
//     }

//     return 0;
// }

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void *HandleRequest(void *arg) {
  //printf("In Handle Request thread\n");

  struct thread_data *data;
  data = (struct thread_data *) arg;
  unsigned char *ptr = data->resp->path;
  unsigned char *ptr_hash = data->resp->path_hash;
  uint32_t* id = data->req->id;
  uint32_t *level= data->req->level;
  uint32_t *d_lev = data->req->d_lev;
  bool *recursion = data->req->recursion;
  

  uint64_t path_hash_size = 2 * (*d_lev) * HASH_LENGTH; // 2 from siblings 		

  uint64_t i = 0;

  while(1) {
    //*id==-1 || *level == -1 || 
    while( *(data->req->block) ) {}
    //printf("APP : Recieved Request\n");

    ls.downloadPath(*id, data->resp->path, data->resp->path_hash, path_hash_size, *level , *d_lev);	
    //printf("APP : Downloaded Path\n");	
    *(data->req->block) = true;
        
    while(*(data->req->block)) {}
    ls.uploadPath(*id, data->resp->new_path, data->resp->new_path_hash, *level, *d_lev);
    //printf("APP : Uploaded Path\n");
    *(data->req->block) = true;

    //pthread_exit(NULL);
  }
    
}

uint64_t timediff(struct timeval *start, struct timeval *end) {
  long seconds,useconds;
  uint64_t mtime;
  seconds  = end->tv_sec  - start->tv_sec;
  useconds = end->tv_usec - start->tv_usec;
  mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
  return mtime;
}

double timetaken(timespec *start, timespec *end) {
  long seconds, nseconds;
  seconds = end->tv_sec - start->tv_sec;
  nseconds = end->tv_nsec - start->tv_nsec;
  double mstime = ( double(seconds * 1000) + double(nseconds/MILLION) );
  return mstime;
}


uint32_t ZT_New_LSORAM( uint32_t num_blocks, uint32_t key_size, uint32_t value_size, uint8_t mode, uint8_t oblivious_type, uint8_t populate_flag) {
  sgx_status_t sgx_return;
  uint32_t instance_id;
  sgx_return = createNewLSORAMInstance(global_eid, &instance_id, key_size, value_size, num_blocks, mode, oblivious_type, populate_flag);

  return instance_id;
}
  
int8_t ZT_LSORAM_insert(uint32_t instance_id, unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char* tag_in, uint32_t tag_size, unsigned char *client_pubkey, uint32_t pubkey_size_x,
       uint32_t pubkey_size_y) { 
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = LSORAMInsert(global_eid, &ret, instance_id, encrypted_request,
               request_size, tag_in, tag_size, client_pubkey, pubkey_size_x+pubkey_size_y, pubkey_size_x, pubkey_size_y);
  return ret;
}

int8_t ZT_LSORAM_oprm_insert_pt(uint32_t instance_id, unsigned char *key_l, 
       uint32_t key_size, unsigned char *value_l, uint32_t value_size) {

  std::vector<tuple *> *LSORAM_store;
  auto search = ls_LSORAM.find(instance_id); 
  if(search != ls_LSORAM.end()) {
    LSORAM_store = search->second;
  }
  else{
    return -1;
  }

  int8_t ret;
  tuple *t = (tuple *) malloc(sizeof(tuple));
  t->key = (unsigned char*) malloc (key_size);
  t->value = (unsigned char*) malloc (value_size);
  memcpy(t->key, key_l, key_size);
  memcpy(t->value, value_l, value_size);
  LSORAM_store->push_back(t);
    
  return ret;
}

int8_t ZT_LSORAM_iprm_insert_pt(uint32_t instance_id, unsigned char *key_l, 
       uint32_t key_size, unsigned char *value_l, uint32_t value_size) {

  int8_t ret;
  sgx_status_t sgx_return;
  sgx_return = LSORAMInsert_pt(global_eid, &ret, instance_id, key_l, 
               key_size, value_l, value_size);  
 
  return ret;
}


int8_t ZT_LSORAM_fetch(uint32_t instance_id, unsigned char *encrypted_request, uint32_t request_size, unsigned char *encrypted_response, 
                       uint32_t response_size, unsigned char* tag_in, unsigned char* tag_out, uint32_t tag_size, 
		       unsigned char *client_pubkey, uint32_t pubkey_size_x, uint32_t pubkey_size_y) { 
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = LSORAMFetch(global_eid, &ret, instance_id, encrypted_request, request_size, encrypted_response, response_size, 
               tag_in, tag_out, tag_size, client_pubkey, pubkey_size_x + pubkey_size_y, pubkey_size_x, pubkey_size_y);
  return ret;
}

int8_t ZT_HSORAM_insert(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type, uint64_t oram_index,
       unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char* tag_in, uint32_t tag_size, unsigned char *client_pubkey, uint32_t pubkey_size_x,
       uint32_t pubkey_size_y) { 
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = HSORAMInsert(global_eid, &ret, lsoram_iid, oram_iid, oram_type, 
               oram_index, encrypted_request, request_size, tag_in, tag_size, 
               client_pubkey, pubkey_size_x+pubkey_size_y, pubkey_size_x,
               pubkey_size_y);
  return ret;
}

int8_t ZT_HSORAM_fetch(uint32_t lsoram_iid, uint32_t oram_iid, uint8_t oram_type, 
       unsigned char *encrypted_request, uint32_t request_size, 
       unsigned char *encrypted_response, uint32_t response_size, 
       unsigned char* tag_in, unsigned char* tag_out, uint32_t tag_size, 
       unsigned char *client_pubkey, uint32_t pubkey_size_x, uint32_t pubkey_size_y) { 
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = HSORAMFetch(global_eid, &ret, lsoram_iid, oram_iid, oram_type,
               encrypted_request, request_size, encrypted_response, response_size, 
               tag_in, tag_out, tag_size, client_pubkey, 
               pubkey_size_x + pubkey_size_y, pubkey_size_x, pubkey_size_y);
  return ret;
}

int8_t ZT_LSORAM_evict(uint32_t id, unsigned char *key, uint32_t key_size) {
  sgx_status_t sgx_return; 
  int8_t ret;
  sgx_return = LSORAMEvict(global_eid, &ret, id, key, key_size);
  return ret;
}

void ZT_LSORAM_delete(uint32_t id) {
  sgx_status_t sgx_return;
  uint8_t ret;
  sgx_return = deleteLSORAMInstance(global_eid, &ret, id);
}

unsigned char *getOutsidePtr_OCALL() {
  unsigned char *ptr = (unsigned char*) malloc (10);
  memcpy(ptr, "ABCD\n", 6);
  return ptr;
}

void* createLSORAM_OCALL(uint32_t id, uint32_t key_size, uint32_t value_size, uint32_t num_blocks_p, uint8_t oblv_mode) {
  std::vector<tuple*> *LSORAM_store = new std::vector<tuple*>();
  ls_LSORAM.insert(std::make_pair(id, LSORAM_store));

  if(oblv_mode == FULL_OBLV) {
    //Instantiate num_blocks_p blocks;
    for(uint8_t i =0; i<num_blocks_p; i++) {
      tuple *t1 = (tuple *) malloc(sizeof(tuple));
      t1->key = (unsigned char*) malloc (key_size);
      t1->value = (unsigned char*) malloc (value_size);
      LSORAM_store->push_back(t1);
   } 
  } 
  else {
    //In ACCESS_OBLV, no need to instantiate blocks
  } 
  return ((void*) LSORAM_store);
}

void* insertLSORAM_OCALL() {
}


void myprintf(char *buffer, uint32_t buffer_size) {
  char buff_temp[buffer_size];
  sprintf(buff_temp, buffer, buffer_size);
  printf("%s", buff_temp);
}

uint8_t uploadPath_OCALL(uint32_t instance_id, uint8_t oram_type, unsigned char* path_array, uint32_t path_size, uint32_t leaf_label, unsigned char* path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level) {
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
    }
    ls->uploadPath(leaf_label, path_array, path_hash, level, D_level);
  }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->uploadPath(leaf_label, path_array, path_hash, level, D_level);
  }
  return 1;
}

uint8_t uploadBucket_OCALL(uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hashsize, uint32_t size_for_level, uint8_t recursion_level) {
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
      ls->uploadBucket(label, serialized_bucket, size_for_level, hash, hashsize, recursion_level);
    }else{
      //printf("Did NOT find corresponding backend in ls_PORAM\n");
    }

  }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->uploadBucket(label, serialized_bucket, size_for_level, hash, hashsize, recursion_level);
   }
  return 1;
}

uint8_t downloadPath_OCALL(uint32_t instance_id, uint8_t oram_type, unsigned char* path_array, uint32_t path_size, uint32_t leaf_label, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level) {	
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
    }
    ls->downloadPath(leaf_label, path_array, path_hash, path_hash_size, level, D_level);
   }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->downloadPath(leaf_label, path_array, path_hash, path_hash_size, level, D_level);
   }

  return 1;
}

uint8_t downloadBucket_OCALL(uint32_t instance_id, uint8_t oram_type, unsigned char* serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char* hash, uint32_t hashsize, uint32_t size_for_level, uint8_t recursion_level) {
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
    }
    ls->downloadBucket(label, serialized_bucket, size_for_level, hash, hashsize, recursion_level);
   }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->downloadBucket(label, serialized_bucket, size_for_level, hash, hashsize, recursion_level);
   }
  return 1;
}

void build_fetchChildHash(uint32_t instance_id, uint8_t oram_type, uint32_t left, uint32_t right, unsigned char* lchild, unsigned char* rchild, uint32_t hash_size, uint32_t recursion_level) {
  LocalStorage *ls;
  if(oram_type==0) {
    auto search = ls_PORAM.find(instance_id); 
    if(search != ls_PORAM.end()) {
      ls = search->second;
    }
    ls->fetchHash(left, lchild, hash_size, recursion_level);
    ls->fetchHash(right, rchild, hash_size, recursion_level);
   }
  else if(oram_type==1) {
    auto search = ls_CORAM.find(instance_id); 
    if(search != ls_CORAM.end()) {
      ls = search->second;
    }
    ls->fetchHash(left,lchild,hash_size, recursion_level);
    ls->fetchHash(right,rchild,hash_size, recursion_level);
   }
}

uint8_t computeRecursionLevels(uint32_t max_blocks, uint32_t recursion_data_size, uint64_t onchip_posmap_memory_limit) {
  uint8_t recursion_levels = 1;
  uint8_t x;
    
  if(recursion_data_size!=0) {		
    recursion_levels = 1;
    x = recursion_data_size / sizeof(uint32_t);
    uint64_t size_pmap0 = max_blocks * sizeof(uint32_t);
    uint64_t cur_pmap0_blocks = max_blocks;

    while(size_pmap0 > onchip_posmap_memory_limit) {
      cur_pmap0_blocks = (uint64_t) ceil((double)cur_pmap0_blocks/(double)x);
      recursion_levels++;
      size_pmap0 = cur_pmap0_blocks * sizeof(uint32_t);
    }

    #ifdef RECURSION_LEVELS_DEBUG
     printf("IN App: max_blocks = %d\n", max_blocks);
     printf("Recursion Levels : %d\n",recursion_levels);
    #endif
  }
  return recursion_levels;
}

#ifdef DETAILED_MICROBENCHMARKER

  void setMicrobenchmarkerParams(uint8_t oram_type, uint32_t num_requests) {
     DET_MB_PARAMS.oram_type = oram_type;
     DET_MB_PARAMS.num_requests = num_requests;
     DET_MB_PARAMS.on = false;
  }

  void initializeMicrobenchmarker() {
   DET_MB_PARAMS.on = false;
   uint8_t recursion_levels = DET_MB_PARAMS.recursion_levels;
   uint32_t num_reqs = DET_MB_PARAMS.num_requests; 

   
  }

  void initiateMicrobenchmarker(det_mb ***TC_MB) {
    DET_MB_PARAMS.on = true;
    MB=TC_MB;
  }

  uint8_t getRecursionLevels() {
    return(DET_MB_PARAMS.recursion_levels);
  }

#endif

void time_report(int report_type, uint8_t level) {
  //Compute based on report_type and update MB.

  clockid_t clk_id = CLOCK_PROCESS_CPUTIME_ID;
  static struct timespec start, end;
  
  #ifdef DETAILED_MICROBENCHMARKER
    if(DET_MB_PARAMS.on == true) {

      if(DET_MB_PARAMS.oram_type==0) {
        //PathORAM part
        if(report_type==PO_POSMAP_START) {
          clock_gettime(clk_id, &start); 
        }
   
        if(report_type==PO_POSMAP_END) {
          clock_gettime(clk_id, &end); 
          double posmap_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][0];
          ptr->posmap_time = posmap_time;
        } 

        if(report_type==PO_DOWNLOAD_PATH_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==PO_DOWNLOAD_PATH_END) {
          clock_gettime(clk_id, &end); 
          double dp_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->download_path_time = dp_time;
        }

        if(report_type==PO_FETCH_BLOCK_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==PO_FETCH_BLOCK_END) {
          clock_gettime(clk_id, &end); 
          double fb_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->fetch_block_time = fb_time;
        }

        if(report_type==PO_EVICTION_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==PO_EVICTION_END) {
          clock_gettime(clk_id, &end); 
          double el_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->eviction_time = el_time;
        }

        if(report_type==PO_UPLOAD_PATH_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==PO_UPLOAD_PATH_END) {
          clock_gettime(clk_id, &end); 
          double up_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->upload_path_time = up_time;
        }
   
      }
      else if(DET_MB_PARAMS.oram_type==1) {
        //CircuitORAM part

        if(report_type==CO_POSMAP_START) {
          clock_gettime(clk_id, &start); 
        }
   
        if(report_type==CO_POSMAP_END) {
          clock_gettime(clk_id, &end); 
          double posmap_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][0];
          ptr->posmap_time = posmap_time;
        } 

        if(report_type==CO_DOWNLOAD_PATH_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==CO_DOWNLOAD_PATH_END) {
          clock_gettime(clk_id, &end); 
          double dp_time = timetaken(&start, &end);
          //printf("Download Time = %f, %d", dp_time, level);
          det_mb *ptr = MB[req_counter][level];
          ptr->download_path_time = dp_time;
        }

        if(report_type==CO_FETCH_BLOCK_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==CO_FETCH_BLOCK_END) {
          clock_gettime(clk_id, &end); 
          double fb_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->fetch_block_time = fb_time;
        }

        if(report_type==CO_UPLOAD_PATH_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==CO_UPLOAD_PATH_END) {
          clock_gettime(clk_id, &end); 
          double up_time = timetaken(&start, &end);
          //printf("Upload Time = %f\n", up_time);
          det_mb *ptr = MB[req_counter][level];
          ptr->upload_path_time = up_time;
        }

        if(report_type==CO_EVICTION_START) {
          clock_gettime(clk_id, &start); 
        } 

        if(report_type==CO_EVICTION_END) {
          clock_gettime(clk_id, &end); 
          double el_time = timetaken(&start, &end);
          det_mb *ptr = MB[req_counter][level];
          ptr->eviction_time = el_time;
        }

      }
    }
  #endif
}


int8_t ZT_Initialize(unsigned char *bin_x, unsigned char* bin_y, 
       unsigned char *bin_r, unsigned char* bin_s, uint32_t buff_size) {
  
  int8_t ret;

  // Initialize the enclave 
  if(initialize_enclave() < 0) {
    printf("Enter a character before exit ...\n");
    getchar();
    return -1; 
  }

  // // Utilize edger8r attributes
  // edger8r_array_attributes();
  // edger8r_pointer_attributes();
  // edger8r_type_attributes();
  // edger8r_function_attributes();

  // // Utilize trusted libraries 
  // ecall_libc_functions();
  // ecall_libcxx_functions();
  // ecall_thread_functions();

  // Extract Public Key and send it over 
  InitializeKeys(global_eid, &ret, bin_x, bin_y, bin_r, bin_s, buff_size);
  return ret;
}

void ZT_Close() {
        sgx_destroy_enclave(global_eid);
}

uint32_t ZT_New( uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t oblivious_flag, uint32_t recursion_data_size, uint32_t oram_type, uint8_t pZ) {
  sgx_status_t sgx_return = SGX_SUCCESS;
  int8_t rt;
  uint8_t urt;
  uint32_t instance_id;
  int8_t recursion_levels;
  LocalStorage *ls_oram = new LocalStorage();    

  // RecursionLevels is really number of levels of ORAM
  // So if no recursion, recursion_levels = 1 
  recursion_levels = computeRecursionLevels(max_blocks, recursion_data_size, MEM_POSMAP_LIMIT);
  printf("APP.cpp : ComputedRecursionLevels = %d", recursion_levels);
    
  uint32_t D = (uint32_t) ceil(log((double)max_blocks/pZ)/log((double)2));
  printf("App.cpp: Parmas for LS : \n \(%d, %d, %d, %d, %d, %d, %d, %d)\n",
         max_blocks,D,pZ,stash_size,data_size + ADDITIONAL_METADATA_SIZE,inmem_flag, recursion_data_size + ADDITIONAL_METADATA_SIZE, recursion_levels);
  
  // LocalStorage Module, just works with recursion_levels 0 to recursion_levels 
  // And functions without treating recursive and non-recursive backends differently
  // Hence recursion_levels passed = recursion_levels,

  ls_oram->setParams(max_blocks,D,pZ,stash_size,data_size + ADDITIONAL_METADATA_SIZE,inmem_flag, recursion_data_size + ADDITIONAL_METADATA_SIZE, recursion_levels);

  #ifdef DETAILED_MICROBENCHMARKER  
   printf("DET_MB_PARAMS.recursion_levels = %d\n", recursion_levels);
   DET_MB_PARAMS.recursion_levels = recursion_levels; 
   // Spawn required variables for microbenchmarker
   initializeMicrobenchmarker();
   // Client flags the DET_MB_PARAMS, by setting a bool ON to start
   // the detailed microbenchmarking 
  #endif
 
  #ifdef EXITLESS_MODE
    int rc;
    pthread_t thread_hreq;
    req_struct.id = (uint32_t*) malloc (4);
    req_struct.level = (uint32_t*) malloc(4);
    req_struct.d_lev = (uint32_t*) malloc(4);
    req_struct.recursion = (bool *) malloc(1);
    req_struct.block = (bool *) malloc(1);

    resp_struct.path = (unsigned char*) malloc(PATH_SIZE_LIMIT);
    resp_struct.path_hash = (unsigned char*) malloc (PATH_SIZE_LIMIT);
    resp_struct.new_path = (unsigned char*) malloc (PATH_SIZE_LIMIT);
    resp_struct.new_path_hash = (unsigned char*) malloc (PATH_SIZE_LIMIT);
    td.req = &req_struct;
    td.resp = &resp_struct;

    *(req_struct.block) = true;
    *(req_struct.id) = 7;

    rc = pthread_create(&thread_hreq, NULL, HandleRequest, (void *)&td);
    if (rc) {
        std::cout << "Error:unable to create thread," << rc << std::endl;
        exit(-1);
    }
  #else

    sgx_return = getNewORAMInstanceID(global_eid, &instance_id, oram_type);
    printf("INSTANCE_ID returned = %d\n", instance_id);  

    if(oram_type==0){
      ls_PORAM.insert(std::make_pair(instance_id, ls_oram));
      printf("Inserted instance_id = %d into ls_PORAM\n", instance_id);
    }
    else if(oram_type==1) {
      ls_CORAM.insert(std::make_pair(instance_id, ls_oram));
      printf("Inserted instance_id = %d into ls_CORAM\n", instance_id);
    }

    uint8_t ret;
    sgx_return = createNewORAMInstance(global_eid, &ret, instance_id, max_blocks, data_size, stash_size, oblivious_flag, recursion_data_size, recursion_levels, oram_type, pZ);
    

  #endif

  #ifdef DEBUG_PRINT
      printf("initialize_oram Successful\n");
  #endif
  return (instance_id);
}


void ZT_Access(uint32_t instance_id, uint8_t oram_type, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size) {

  #ifdef DETAILED_MICROBENCHMARKER
    static struct timespec start, end;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
  #endif

    accessInterface(global_eid, instance_id, oram_type, encrypted_request, encrypted_response, tag_in, tag_out, request_size, response_size, tag_size);
  
  #ifdef DETAILED_MICROBENCHMARKER
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
    double total_time = timetaken(&start, &end);

    if(DET_MB_PARAMS.on == true) {
      MB[req_counter][0]->total_time=total_time;
      req_counter++; 
        if(DET_MB_PARAMS.num_requests==req_counter) { 
          req_counter=0;
          DET_MB_PARAMS.on = false;
        }
    }
  #endif
 
}

void ZT_Bulk_Read(uint32_t instance_id, uint8_t oram_type, uint32_t no_of_requests, unsigned char *encrypted_request, unsigned char *encrypted_response, unsigned char *tag_in, unsigned char* tag_out, uint32_t request_size, uint32_t response_size, uint32_t tag_size) {
    accessBulkReadInterface(global_eid, instance_id, oram_type, no_of_requests, encrypted_request, encrypted_response, tag_in, tag_out, request_size, response_size, tag_size);
}


void getParams(int argc, char* argv[])
{
  printf("Started getParams\n");
  if(argc!=NUM_EXPECTED_PARAMS) {
    printf("Command line parameters error, received: %d, expected :%d\n",
           argc, NUM_EXPECTED_PARAMS);
    printf(" <N> <No_of_requests> <Stash_size> <Data_block_size> <\"resume\"/\"new\"> <\"memory\"/\"hdd\"> <0/1 = Non-oblivious/Oblivious> <Recursion_block_size> <\"auto\"/\"path\"/\"circuit\"> <Z> <bulk_batch_size> <LogFile>\n\n");
    exit(0);
  }
  printf("argv1: %s\n", argv[1]);
  std::string str = argv[1];
  MAX_BLOCKS = std::stoi(str);
  printf("argv2: %s\n", argv[2]);
  str = argv[2];
  REQUEST_LENGTH = std::stoi(str);
  
  printf("argv3: %s\n", argv[3]);
  str = argv[3];
  STASH_SIZE = std::stoi(str);
  printf("argv4: %s\n", argv[4]);
  str = argv[4];
  DATA_SIZE = std::stoi(str);	
        str = argv[5];
  if(str=="resume")
    RESUME_EXPERIMENT = true;
  str = argv[6];
  if(str=="1")
    OBLIVIOUS_FLAG = 1;
  str = argv[7];	
  RECURSION_DATA_SIZE = std::stoi(str);

  str = argv[8];
  if(str=="path")
    ORAM_TYPE = 0;
  if(str=="circuit")
    ORAM_TYPE = 1;
  str=argv[9];
  Z = std::stoi(str);
  str=argv[10];
  bulk_batch_size = std::stoi(str);
  str = argv[11];
  log_file = str;
  std::string qfile_name = "ZT_"+std::to_string(MAX_BLOCKS)+"_"+std::to_string(DATA_SIZE);
  iquery_file = fopen(qfile_name.c_str(),"w");
}


struct node{
  uint32_t id;
  uint32_t data;
  struct node *left, *right;
};

int initializeZeroTrace() {
  // Variables for Enclave Public Key retrieval 
  uint32_t max_buff_size = PRIME256V1_KEY_SIZE;
  unsigned char bin_x[PRIME256V1_KEY_SIZE], bin_y[PRIME256V1_KEY_SIZE], signature_r[PRIME256V1_KEY_SIZE], signature_s[PRIME256V1_KEY_SIZE];
  
  ZT_Initialize(bin_x, bin_y, signature_r, signature_s, max_buff_size);
  
  EC_GROUP *curve;
  EC_KEY *enclave_verification_key = NULL;
  ECDSA_SIG *sig_enclave = ECDSA_SIG_new();	
  BIGNUM *x, *y, *xh, *yh, *sig_r, *sig_s;
  BN_CTX *bn_ctx = BN_CTX_new();
  int ret;

  if(NULL == (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)))
	  printf("Setting EC_GROUP failed \n");

  EC_POINT *pub_point = EC_POINT_new(curve);
  //Verify the Enclave Public Key
  enclave_verification_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  xh = BN_bin2bn(hardcoded_verification_key_x, PRIME256V1_KEY_SIZE, NULL);
  yh = BN_bin2bn(hardcoded_verification_key_y, PRIME256V1_KEY_SIZE, NULL);
  EC_KEY_set_public_key_affine_coordinates(enclave_verification_key, xh, yh);
  unsigned char *serialized_public_key = (unsigned char*) malloc (PRIME256V1_KEY_SIZE*2);
  memcpy(serialized_public_key, bin_x, PRIME256V1_KEY_SIZE);
  memcpy(serialized_public_key + PRIME256V1_KEY_SIZE, bin_y, PRIME256V1_KEY_SIZE);
	  
  sig_enclave->r = BN_bin2bn(signature_r, PRIME256V1_KEY_SIZE, NULL);
  sig_enclave->s = BN_bin2bn(signature_s, PRIME256V1_KEY_SIZE, NULL);	
  
  ret = ECDSA_do_verify((const unsigned char*) serialized_public_key, PRIME256V1_KEY_SIZE*2, sig_enclave, enclave_verification_key);
  if(ret==1){
	  printf("GetEnclavePublishedKey : Verification Successful! \n");
  }
  else{
	  printf("GetEnclavePublishedKey : Verification FAILED! \n");
  }
  
  //Load the Enclave Public Key
  ENCLAVE_PUBLIC_KEY = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  
  x = BN_bin2bn(bin_x, PRIME256V1_KEY_SIZE, NULL);
  y = BN_bin2bn(bin_y, PRIME256V1_KEY_SIZE, NULL);
  if(EC_POINT_set_affine_coordinates_GFp(curve, pub_point, x, y, bn_ctx)==0)
	  printf("EC_POINT_set_affine_coordinates FAILED \n");

  if(EC_KEY_set_public_key(ENCLAVE_PUBLIC_KEY, pub_point)==0)
	  printf("EC_KEY_set_public_key FAILED \n");

  BN_CTX_free(bn_ctx);
  free(serialized_public_key);

}

/* Application entry */

void zt_map_init(int n)
{
  uint32_t encrypted_request_size;
  request_size = ID_SIZE_IN_BYTES + DATA_SIZE;
  tag_in = (unsigned char*) malloc (TAG_SIZE);
  tag_out = (unsigned char*) malloc (TAG_SIZE);
  data_in = (unsigned char*) malloc (DATA_SIZE);
  uint32_t instance_id = 0;	
      response_size = DATA_SIZE;
    //+1 for simplicity printing a null-terminated string
    data_out = (unsigned char*) malloc (DATA_SIZE + 1);

    encrypted_request_size = computeCiphertextSize(DATA_SIZE);
    encrypted_request = (unsigned char *) malloc (encrypted_request_size);				
    encrypted_response = (unsigned char *) malloc (response_size);		
  for (int i = 0; i < n; i++)
  {
      
      static sgx_aes_gcm_128bit_key_t key_test = { 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51 };
      key_test[i % 16] = (i * i + 2) % 255;
      //generate_request_start = clock();
      memcpy(data_in, key_test, 16);
      encryptRequest(i, 'w', data_in, DATA_SIZE, encrypted_request, tag_in, encrypted_request_size);
      //generate_request_stop = clock();		

      //Process Request:
      // process_request_start = clock();		
      ZT_Access(instance_id, ORAM_TYPE, encrypted_request, encrypted_response, tag_in, tag_out, encrypted_request_size, response_size, TAG_SIZE);
       // printf("encrypted request id: %d, size: %d, data: %s\n", i, encrypted_request_size, encrypted_request);
      // process_request_stop = clock();		
  }
}

int socket_init()
{
	
    int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
	int PORT = 8080;
    int addrlen = sizeof(address); 
    char *hello = "Hello from server"; 
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    } 
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    } 
	return new_socket;
}

void profile_serialisation(char *dst, User src)
{
	int index = 0;
	memcpy(dst, &src.uid, sizeof(src.uid));
	index += sizeof(src.uid);
	memcpy(dst+index, src.fname, sizeof(src.fname));
	index += sizeof(src.fname);
	memcpy(dst+index, src.lname, sizeof(src.lname));
	index += sizeof(src.lname);
	memcpy(dst+index, &src.age, sizeof(src.age));
	index += sizeof(src.age);
	memcpy(dst+index, &src.gender, sizeof(src.gender));
	index += sizeof(src.gender);
	memcpy(dst+index, src.location, sizeof(src.location));
	index += sizeof(src.location);
	memcpy(dst+index, src.hobby, sizeof(src.hobby));
}

typedef struct secret_wrapper {
	size_t len;
	char *cb;
}cb_wrapper;

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
int main(int argc, char *argv[])
{
  //getParams(argc, argv);
  //  (void)(argc);
  //  (void)(argv);

     /* Initialize the enclave */
      if(initialize_enclave() < 0){
          printf("Enter a character before exit ...\n");
          getchar();
          return -1; 
      }
	
	std::unordered_map<std::string, cb_wrapper> MT;
	int current_user_id, socket_id;
	ecall_libcxx_sys_init();
	// socket_id = socket_init();
	ecall_libcxx_sys_reg(&current_user_id);
	// receives user id from enclave.
	printf("user id %d is registered in enclave.\n", current_user_id);	
	// Assuming the Remote Attestation is done and we have received a profile securely.
	User profile = { current_user_id, "First Name", "Last Name", 1222225, 1, "Melbourne", "Coding" };
    printf("Size of profile = %d, profile.id = %d, .fname = %d, .lname = %d, .age = %d, .gender = %d, .location = %d, .hobby = %d.\n",
	sizeof(profile),sizeof(profile.uid), sizeof(profile.fname), sizeof(profile.lname), sizeof(profile.age), sizeof(profile.gender), sizeof(profile.location), sizeof(profile.hobby));
	char *serialised_profile = (char*)malloc(sizeof(profile));
	profile_serialisation(serialised_profile, profile);
	printf("Serialised profile: ");
	for (int i = 0; i < sizeof(profile); i++)
		printf("%c ", serialised_profile[i]);
	printf("\n");	

	// encryption for profile
	size_t enc_profile_size = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + sizeof(profile));
	char *enc_profile = (char*)malloc(enc_profile_size);
	ecall_libcxx_encrypt(serialised_profile, sizeof(profile), enc_profile, enc_profile_size, current_user_id);
	printf("Encrypted profile: ");
	for (int i = 0; i < enc_profile_size; i++)
		printf("%x ", (unsigned char)enc_profile[i]);
	printf("\n");

	// Assuming we have got the encrypted profile from user, next step is to compute search token
	// STA, STB along with secret CA,CB that relate to STA and STB
	
	// As each attribute contains two search token, STA and STB, where the size of each is 16 bytes (128 bits)
	// using MD5, given the number of attributes in a profile, size of search tokens can be computed.
	size_t search_token_size = (64 * 4) + 1;
	char *search_token = (char*)malloc(search_token_size);
	size_t secret_token_size = ((SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + 4) * 4) + search_token_size; 
	char *secret_token = (char*)malloc(secret_token_size);
	printf("search_token size before ecall: %d, secret_size before ecall: %d\n", search_token_size, secret_token_size);
	ecall_libcxx_sys_search_token_computation(enc_profile, enc_profile_size, search_token, search_token_size, secret_token, secret_token_size, current_user_id);
	printf("finished token computation, token result: %s\n", search_token);
	// decryption for profile
	size_t dec_profile_size = sizeof(profile);
	char *dec_profile = (char*)malloc(dec_profile_size);
	ecall_libcxx_decrypt(enc_profile, enc_profile_size, dec_profile, dec_profile_size, current_user_id);
	printf("Decrypted profile: ");
	for (int i = 0; i < dec_profile_size; i++)
		printf("%c ", (unsigned char)dec_profile[i]);
	printf("\n");
	printf("search_token after ecall: ");
	for (int i = 0; i < search_token_size; i++)
		printf("%c ", (unsigned char)search_token[i]);
	printf("\n");
	printf("secret_token after ecall: ");
	for (int i = 0; i < secret_token_size; i++)
		printf("%c ", (char)secret_token[i]);
	printf("\n");
	
	int secret_token_offset = 0;
	int cb_size = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + 4);
	for (int i = 0; i < 4; i++)
	{
		
		char ca_raw[65] = { 0 };
		memcpy(ca_raw, secret_token+secret_token_offset, 64);
		ca_raw[64] = '\0';
		secret_token_offset += 64;
		printf("ca for %d attribute: %s\n", i, ca_raw);
		std::string ca_str = ca_raw;
		cb_wrapper cb = {.len = cb_size};
		cb.cb = (char*)malloc(cb.len);
		memcpy(cb.cb, secret_token+secret_token_offset, cb.len);
		secret_token_offset += cb_size;
		MT.insert(std::pair<std::string, cb_wrapper>(ca_str, cb));
		
	}

// Assuming we have got the search token STA, STB.
// It iterates through every combination of STA + index to find CA
// and decrypts it using STB as key.

for (int i = 0; i < search_token_size; i += 48)
{
	char *STA = (char*)malloc(32);
	char *STB = (char*)malloc(16);	
	char *sha256_digest_buffer = (char*)malloc(36);
	int counter = 0;
	char c1_out_str[65] = { 0 };
	unsigned char *c1_out_raw = (unsigned char*)malloc(32);
	memcpy(STA, search_token+i, 32);
	memcpy(STB, search_token+i+32, 16);
	memcpy(sha256_digest_buffer, STA, 32);
	memcpy(sha256_digest_buffer+32, &counter, 4);	
	sha256(sha256_digest_buffer, c1_out_str, c1_out_raw);	
	c1_out_str[64] = '\0';
	printf("CA: %s\n", c1_out_str);
	std::unordered_map<std::string,cb_wrapper>::iterator it;
	it = MT.find(std::string(c1_out_str));
	if (it == MT.end())
		continue;
	
	size_t dec_message_len = 4;
	char *dec_message = (char*)malloc(dec_message_len);
	ecall_libcxx_decrypt_with_key(it->second.cb, cb_size, dec_message, dec_message_len, STB, 16);
	printf("CA: %s, CB: ", it->first.c_str());
	for (int i = 0; i < 4; i++)
		printf("%02x ", (unsigned char)dec_message[i]);
	printf("\n");
}
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    printf("Info: Cxx11DemoEnclave successfully returned.\n");

    //printf("Enter a character before exit ...\n");
    //getchar();
	
    return 0;
}

