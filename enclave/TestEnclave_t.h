#ifndef TESTENCLAVE_T_H__
#define TESTENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "../app/pdp.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void test(void);
void ecall_verify(char** optarg, long int st_size);

sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL pdp_tag_file(int* retval, char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len);
sgx_status_t SGX_CDECL pdp_challenge_file(PDP_challenge** retval, unsigned int numfileblocks);
sgx_status_t SGX_CDECL pdp_prove_file(PDP_proof** retval, char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len, PDP_challenge* challenge, PDP_key* key);
sgx_status_t SGX_CDECL pdp_verify_file(int* retval, PDP_challenge* challenge, PDP_proof* proof);
sgx_status_t SGX_CDECL pdp_challenge_and_verify_file(int* retval, char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len);
sgx_status_t SGX_CDECL read_pdp_tag(PDP_tag** retval, FILE* tagfile, unsigned int index);
sgx_status_t SGX_CDECL pdp_tag_block(PDP_tag** retval, PDP_key* key, unsigned char* block, size_t blocksize, unsigned int index);
sgx_status_t SGX_CDECL pdp_challenge(PDP_challenge** retval, PDP_key* key, unsigned int numfileblocks);
sgx_status_t SGX_CDECL pdp_generate_proof_update(PDP_proof** retval, PDP_key* key, PDP_challenge* challenge, PDP_tag* tag, PDP_proof* proof, unsigned char* block, size_t blocksize, unsigned int j);
sgx_status_t SGX_CDECL pdp_generate_proof_final(PDP_proof** retval, PDP_key* key, PDP_challenge* challenge, PDP_proof* proof);
sgx_status_t SGX_CDECL pdp_verify_proof(int* retval, PDP_key* key, PDP_challenge* challenge, PDP_proof* proof);
sgx_status_t SGX_CDECL pdp_create_new_keypair(PDP_key** retval);
sgx_status_t SGX_CDECL pdp_get_keypair(PDP_key** retval);
sgx_status_t SGX_CDECL pdp_get_pubkey(PDP_key** retval);
sgx_status_t SGX_CDECL generate_pdp_key(PDP_key** retval);
sgx_status_t SGX_CDECL destroy_pdp_key(PDP_key* key);
sgx_status_t SGX_CDECL sfree(void* ptr, size_t size);
sgx_status_t SGX_CDECL sanitize_pdp_challenge(PDP_challenge** retval, PDP_challenge* challenge);
sgx_status_t SGX_CDECL generate_prp_pi(unsigned int** retval, PDP_challenge* challenge);
sgx_status_t SGX_CDECL generate_H(unsigned char** retval, BIGNUM* input, size_t* H_result_size);
sgx_status_t SGX_CDECL generate_prf_f(unsigned char** retval, PDP_challenge* challenge, unsigned int j, size_t* prf_result_size);
sgx_status_t SGX_CDECL generate_prf_w(unsigned char** retval, PDP_key* key, unsigned int index, size_t* prf_result_size);
sgx_status_t SGX_CDECL generate_fdh_h(BIGNUM** retval, PDP_key* key, unsigned char* index_prf, size_t index_prf_size);
sgx_status_t SGX_CDECL pick_pdp_generator(PDP_generator** retval, BIGNUM* n);
sgx_status_t SGX_CDECL destroy_pdp_generator(PDP_generator* g);
sgx_status_t SGX_CDECL generate_pdp_tag(PDP_tag** retval);
sgx_status_t SGX_CDECL destroy_pdp_tag(PDP_tag* tag);
sgx_status_t SGX_CDECL generate_pdp_challenge(PDP_challenge** retval);
sgx_status_t SGX_CDECL destroy_pdp_challenge(PDP_challenge* challenge);
sgx_status_t SGX_CDECL generate_pdp_proof(PDP_proof** retval);
sgx_status_t SGX_CDECL destroy_pdp_proof(PDP_proof* proof);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
