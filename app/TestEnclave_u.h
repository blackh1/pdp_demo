#ifndef TESTENCLAVE_U_H__
#define TESTENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "../app/pdp.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UPRINT_DEFINED__
#define UPRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, uprint, (const char* str));
#endif
#ifndef PDP_TAG_FILE_DEFINED__
#define PDP_TAG_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, pdp_tag_file, (char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len));
#endif
#ifndef PDP_CHALLENGE_FILE_DEFINED__
#define PDP_CHALLENGE_FILE_DEFINED__
PDP_challenge* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_challenge_file, (unsigned int numfileblocks));
#endif
#ifndef PDP_PROVE_FILE_DEFINED__
#define PDP_PROVE_FILE_DEFINED__
PDP_proof* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_prove_file, (char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len, PDP_challenge* challenge, PDP_key* key));
#endif
#ifndef PDP_VERIFY_FILE_DEFINED__
#define PDP_VERIFY_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, pdp_verify_file, (PDP_challenge* challenge, PDP_proof* proof));
#endif
#ifndef PDP_CHALLENGE_AND_VERIFY_FILE_DEFINED__
#define PDP_CHALLENGE_AND_VERIFY_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, pdp_challenge_and_verify_file, (char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len));
#endif
#ifndef READ_PDP_TAG_DEFINED__
#define READ_PDP_TAG_DEFINED__
PDP_tag* SGX_UBRIDGE(SGX_NOCONVENTION, read_pdp_tag, (FILE* tagfile, unsigned int index));
#endif
#ifndef PDP_TAG_BLOCK_DEFINED__
#define PDP_TAG_BLOCK_DEFINED__
PDP_tag* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_tag_block, (PDP_key* key, unsigned char* block, size_t blocksize, unsigned int index));
#endif
#ifndef PDP_CHALLENGE_DEFINED__
#define PDP_CHALLENGE_DEFINED__
PDP_challenge* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_challenge, (PDP_key* key, unsigned int numfileblocks));
#endif
#ifndef PDP_GENERATE_PROOF_UPDATE_DEFINED__
#define PDP_GENERATE_PROOF_UPDATE_DEFINED__
PDP_proof* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_generate_proof_update, (PDP_key* key, PDP_challenge* challenge, PDP_tag* tag, PDP_proof* proof, unsigned char* block, size_t blocksize, unsigned int j));
#endif
#ifndef PDP_GENERATE_PROOF_FINAL_DEFINED__
#define PDP_GENERATE_PROOF_FINAL_DEFINED__
PDP_proof* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_generate_proof_final, (PDP_key* key, PDP_challenge* challenge, PDP_proof* proof));
#endif
#ifndef PDP_VERIFY_PROOF_DEFINED__
#define PDP_VERIFY_PROOF_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, pdp_verify_proof, (PDP_key* key, PDP_challenge* challenge, PDP_proof* proof));
#endif
#ifndef PDP_CREATE_NEW_KEYPAIR_DEFINED__
#define PDP_CREATE_NEW_KEYPAIR_DEFINED__
PDP_key* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_create_new_keypair, (void));
#endif
#ifndef PDP_GET_KEYPAIR_DEFINED__
#define PDP_GET_KEYPAIR_DEFINED__
PDP_key* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_get_keypair, (void));
#endif
#ifndef PDP_GET_PUBKEY_DEFINED__
#define PDP_GET_PUBKEY_DEFINED__
PDP_key* SGX_UBRIDGE(SGX_NOCONVENTION, pdp_get_pubkey, (void));
#endif
#ifndef GENERATE_PDP_KEY_DEFINED__
#define GENERATE_PDP_KEY_DEFINED__
PDP_key* SGX_UBRIDGE(SGX_NOCONVENTION, generate_pdp_key, (void));
#endif
#ifndef DESTROY_PDP_KEY_DEFINED__
#define DESTROY_PDP_KEY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, destroy_pdp_key, (PDP_key* key));
#endif
#ifndef SFREE_DEFINED__
#define SFREE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, sfree, (void* ptr, size_t size));
#endif
#ifndef SANITIZE_PDP_CHALLENGE_DEFINED__
#define SANITIZE_PDP_CHALLENGE_DEFINED__
PDP_challenge* SGX_UBRIDGE(SGX_NOCONVENTION, sanitize_pdp_challenge, (PDP_challenge* challenge));
#endif
#ifndef GENERATE_PRP_PI_DEFINED__
#define GENERATE_PRP_PI_DEFINED__
unsigned int* SGX_UBRIDGE(SGX_NOCONVENTION, generate_prp_pi, (PDP_challenge* challenge));
#endif
#ifndef GENERATE_H_DEFINED__
#define GENERATE_H_DEFINED__
unsigned char* SGX_UBRIDGE(SGX_NOCONVENTION, generate_H, (BIGNUM* input, size_t* H_result_size));
#endif
#ifndef GENERATE_PRF_F_DEFINED__
#define GENERATE_PRF_F_DEFINED__
unsigned char* SGX_UBRIDGE(SGX_NOCONVENTION, generate_prf_f, (PDP_challenge* challenge, unsigned int j, size_t* prf_result_size));
#endif
#ifndef GENERATE_PRF_W_DEFINED__
#define GENERATE_PRF_W_DEFINED__
unsigned char* SGX_UBRIDGE(SGX_NOCONVENTION, generate_prf_w, (PDP_key* key, unsigned int index, size_t* prf_result_size));
#endif
#ifndef GENERATE_FDH_H_DEFINED__
#define GENERATE_FDH_H_DEFINED__
BIGNUM* SGX_UBRIDGE(SGX_NOCONVENTION, generate_fdh_h, (PDP_key* key, unsigned char* index_prf, size_t index_prf_size));
#endif
#ifndef PICK_PDP_GENERATOR_DEFINED__
#define PICK_PDP_GENERATOR_DEFINED__
PDP_generator* SGX_UBRIDGE(SGX_NOCONVENTION, pick_pdp_generator, (BIGNUM* n));
#endif
#ifndef DESTROY_PDP_GENERATOR_DEFINED__
#define DESTROY_PDP_GENERATOR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, destroy_pdp_generator, (PDP_generator* g));
#endif
#ifndef GENERATE_PDP_TAG_DEFINED__
#define GENERATE_PDP_TAG_DEFINED__
PDP_tag* SGX_UBRIDGE(SGX_NOCONVENTION, generate_pdp_tag, (void));
#endif
#ifndef DESTROY_PDP_TAG_DEFINED__
#define DESTROY_PDP_TAG_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, destroy_pdp_tag, (PDP_tag* tag));
#endif
#ifndef GENERATE_PDP_CHALLENGE_DEFINED__
#define GENERATE_PDP_CHALLENGE_DEFINED__
PDP_challenge* SGX_UBRIDGE(SGX_NOCONVENTION, generate_pdp_challenge, (void));
#endif
#ifndef DESTROY_PDP_CHALLENGE_DEFINED__
#define DESTROY_PDP_CHALLENGE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, destroy_pdp_challenge, (PDP_challenge* challenge));
#endif
#ifndef GENERATE_PDP_PROOF_DEFINED__
#define GENERATE_PDP_PROOF_DEFINED__
PDP_proof* SGX_UBRIDGE(SGX_NOCONVENTION, generate_pdp_proof, (void));
#endif
#ifndef DESTROY_PDP_PROOF_DEFINED__
#define DESTROY_PDP_PROOF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, destroy_pdp_proof, (PDP_proof* proof));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif

sgx_status_t test(sgx_enclave_id_t eid);
sgx_status_t ecall_verify(sgx_enclave_id_t eid, char** optarg, long int st_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
