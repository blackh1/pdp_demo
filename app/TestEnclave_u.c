#include "TestEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_verify_t {
	char** ms_optarg;
	long int ms_st_size;
} ms_ecall_verify_t;

typedef struct ms_uprint_t {
	const char* ms_str;
} ms_uprint_t;

typedef struct ms_pdp_tag_file_t {
	int ms_retval;
	char* ms_filepath;
	size_t ms_filepath_len;
	char* ms_tagfilepath;
	size_t ms_tagfilepath_len;
} ms_pdp_tag_file_t;

typedef struct ms_pdp_challenge_file_t {
	PDP_challenge* ms_retval;
	unsigned int ms_numfileblocks;
} ms_pdp_challenge_file_t;

typedef struct ms_pdp_prove_file_t {
	PDP_proof* ms_retval;
	char* ms_filepath;
	size_t ms_filepath_len;
	char* ms_tagfilepath;
	size_t ms_tagfilepath_len;
	PDP_challenge* ms_challenge;
	PDP_key* ms_key;
} ms_pdp_prove_file_t;

typedef struct ms_pdp_verify_file_t {
	int ms_retval;
	PDP_challenge* ms_challenge;
	PDP_proof* ms_proof;
} ms_pdp_verify_file_t;

typedef struct ms_pdp_challenge_and_verify_file_t {
	int ms_retval;
	char* ms_filepath;
	size_t ms_filepath_len;
	char* ms_tagfilepath;
	size_t ms_tagfilepath_len;
} ms_pdp_challenge_and_verify_file_t;

typedef struct ms_read_pdp_tag_t {
	PDP_tag* ms_retval;
	FILE* ms_tagfile;
	unsigned int ms_index;
} ms_read_pdp_tag_t;

typedef struct ms_pdp_tag_block_t {
	PDP_tag* ms_retval;
	PDP_key* ms_key;
	unsigned char* ms_block;
	size_t ms_blocksize;
	unsigned int ms_index;
} ms_pdp_tag_block_t;

typedef struct ms_pdp_challenge_t {
	PDP_challenge* ms_retval;
	PDP_key* ms_key;
	unsigned int ms_numfileblocks;
} ms_pdp_challenge_t;

typedef struct ms_pdp_generate_proof_update_t {
	PDP_proof* ms_retval;
	PDP_key* ms_key;
	PDP_challenge* ms_challenge;
	PDP_tag* ms_tag;
	PDP_proof* ms_proof;
	unsigned char* ms_block;
	size_t ms_blocksize;
	unsigned int ms_j;
} ms_pdp_generate_proof_update_t;

typedef struct ms_pdp_generate_proof_final_t {
	PDP_proof* ms_retval;
	PDP_key* ms_key;
	PDP_challenge* ms_challenge;
	PDP_proof* ms_proof;
} ms_pdp_generate_proof_final_t;

typedef struct ms_pdp_verify_proof_t {
	int ms_retval;
	PDP_key* ms_key;
	PDP_challenge* ms_challenge;
	PDP_proof* ms_proof;
} ms_pdp_verify_proof_t;

typedef struct ms_pdp_create_new_keypair_t {
	PDP_key* ms_retval;
} ms_pdp_create_new_keypair_t;

typedef struct ms_pdp_get_keypair_t {
	PDP_key* ms_retval;
} ms_pdp_get_keypair_t;

typedef struct ms_pdp_get_pubkey_t {
	PDP_key* ms_retval;
} ms_pdp_get_pubkey_t;

typedef struct ms_generate_pdp_key_t {
	PDP_key* ms_retval;
} ms_generate_pdp_key_t;

typedef struct ms_destroy_pdp_key_t {
	PDP_key* ms_key;
} ms_destroy_pdp_key_t;

typedef struct ms_sfree_t {
	void* ms_ptr;
	size_t ms_size;
} ms_sfree_t;

typedef struct ms_sanitize_pdp_challenge_t {
	PDP_challenge* ms_retval;
	PDP_challenge* ms_challenge;
} ms_sanitize_pdp_challenge_t;

typedef struct ms_generate_prp_pi_t {
	unsigned int* ms_retval;
	PDP_challenge* ms_challenge;
} ms_generate_prp_pi_t;

typedef struct ms_generate_H_t {
	unsigned char* ms_retval;
	BIGNUM* ms_input;
	size_t* ms_H_result_size;
} ms_generate_H_t;

typedef struct ms_generate_prf_f_t {
	unsigned char* ms_retval;
	PDP_challenge* ms_challenge;
	unsigned int ms_j;
	size_t* ms_prf_result_size;
} ms_generate_prf_f_t;

typedef struct ms_generate_prf_w_t {
	unsigned char* ms_retval;
	PDP_key* ms_key;
	unsigned int ms_index;
	size_t* ms_prf_result_size;
} ms_generate_prf_w_t;

typedef struct ms_generate_fdh_h_t {
	BIGNUM* ms_retval;
	PDP_key* ms_key;
	unsigned char* ms_index_prf;
	size_t ms_index_prf_size;
} ms_generate_fdh_h_t;

typedef struct ms_pick_pdp_generator_t {
	PDP_generator* ms_retval;
	BIGNUM* ms_n;
} ms_pick_pdp_generator_t;

typedef struct ms_destroy_pdp_generator_t {
	PDP_generator* ms_g;
} ms_destroy_pdp_generator_t;

typedef struct ms_generate_pdp_tag_t {
	PDP_tag* ms_retval;
} ms_generate_pdp_tag_t;

typedef struct ms_destroy_pdp_tag_t {
	PDP_tag* ms_tag;
} ms_destroy_pdp_tag_t;

typedef struct ms_generate_pdp_challenge_t {
	PDP_challenge* ms_retval;
} ms_generate_pdp_challenge_t;

typedef struct ms_destroy_pdp_challenge_t {
	PDP_challenge* ms_challenge;
} ms_destroy_pdp_challenge_t;

typedef struct ms_generate_pdp_proof_t {
	PDP_proof* ms_retval;
} ms_generate_pdp_proof_t;

typedef struct ms_destroy_pdp_proof_t {
	PDP_proof* ms_proof;
} ms_destroy_pdp_proof_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL TestEnclave_uprint(void* pms)
{
	ms_uprint_t* ms = SGX_CAST(ms_uprint_t*, pms);
	uprint(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_tag_file(void* pms)
{
	ms_pdp_tag_file_t* ms = SGX_CAST(ms_pdp_tag_file_t*, pms);
	ms->ms_retval = pdp_tag_file(ms->ms_filepath, ms->ms_filepath_len, ms->ms_tagfilepath, ms->ms_tagfilepath_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_challenge_file(void* pms)
{
	ms_pdp_challenge_file_t* ms = SGX_CAST(ms_pdp_challenge_file_t*, pms);
	ms->ms_retval = pdp_challenge_file(ms->ms_numfileblocks);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_prove_file(void* pms)
{
	ms_pdp_prove_file_t* ms = SGX_CAST(ms_pdp_prove_file_t*, pms);
	ms->ms_retval = pdp_prove_file(ms->ms_filepath, ms->ms_filepath_len, ms->ms_tagfilepath, ms->ms_tagfilepath_len, ms->ms_challenge, ms->ms_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_verify_file(void* pms)
{
	ms_pdp_verify_file_t* ms = SGX_CAST(ms_pdp_verify_file_t*, pms);
	ms->ms_retval = pdp_verify_file(ms->ms_challenge, ms->ms_proof);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_challenge_and_verify_file(void* pms)
{
	ms_pdp_challenge_and_verify_file_t* ms = SGX_CAST(ms_pdp_challenge_and_verify_file_t*, pms);
	ms->ms_retval = pdp_challenge_and_verify_file(ms->ms_filepath, ms->ms_filepath_len, ms->ms_tagfilepath, ms->ms_tagfilepath_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_read_pdp_tag(void* pms)
{
	ms_read_pdp_tag_t* ms = SGX_CAST(ms_read_pdp_tag_t*, pms);
	ms->ms_retval = read_pdp_tag(ms->ms_tagfile, ms->ms_index);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_tag_block(void* pms)
{
	ms_pdp_tag_block_t* ms = SGX_CAST(ms_pdp_tag_block_t*, pms);
	ms->ms_retval = pdp_tag_block(ms->ms_key, ms->ms_block, ms->ms_blocksize, ms->ms_index);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_challenge(void* pms)
{
	ms_pdp_challenge_t* ms = SGX_CAST(ms_pdp_challenge_t*, pms);
	ms->ms_retval = pdp_challenge(ms->ms_key, ms->ms_numfileblocks);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_generate_proof_update(void* pms)
{
	ms_pdp_generate_proof_update_t* ms = SGX_CAST(ms_pdp_generate_proof_update_t*, pms);
	ms->ms_retval = pdp_generate_proof_update(ms->ms_key, ms->ms_challenge, ms->ms_tag, ms->ms_proof, ms->ms_block, ms->ms_blocksize, ms->ms_j);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_generate_proof_final(void* pms)
{
	ms_pdp_generate_proof_final_t* ms = SGX_CAST(ms_pdp_generate_proof_final_t*, pms);
	ms->ms_retval = pdp_generate_proof_final(ms->ms_key, ms->ms_challenge, ms->ms_proof);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_verify_proof(void* pms)
{
	ms_pdp_verify_proof_t* ms = SGX_CAST(ms_pdp_verify_proof_t*, pms);
	ms->ms_retval = pdp_verify_proof(ms->ms_key, ms->ms_challenge, ms->ms_proof);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_create_new_keypair(void* pms)
{
	ms_pdp_create_new_keypair_t* ms = SGX_CAST(ms_pdp_create_new_keypair_t*, pms);
	ms->ms_retval = pdp_create_new_keypair();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_get_keypair(void* pms)
{
	ms_pdp_get_keypair_t* ms = SGX_CAST(ms_pdp_get_keypair_t*, pms);
	ms->ms_retval = pdp_get_keypair();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pdp_get_pubkey(void* pms)
{
	ms_pdp_get_pubkey_t* ms = SGX_CAST(ms_pdp_get_pubkey_t*, pms);
	ms->ms_retval = pdp_get_pubkey();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_pdp_key(void* pms)
{
	ms_generate_pdp_key_t* ms = SGX_CAST(ms_generate_pdp_key_t*, pms);
	ms->ms_retval = generate_pdp_key();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_destroy_pdp_key(void* pms)
{
	ms_destroy_pdp_key_t* ms = SGX_CAST(ms_destroy_pdp_key_t*, pms);
	destroy_pdp_key(ms->ms_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sfree(void* pms)
{
	ms_sfree_t* ms = SGX_CAST(ms_sfree_t*, pms);
	sfree(ms->ms_ptr, ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sanitize_pdp_challenge(void* pms)
{
	ms_sanitize_pdp_challenge_t* ms = SGX_CAST(ms_sanitize_pdp_challenge_t*, pms);
	ms->ms_retval = sanitize_pdp_challenge(ms->ms_challenge);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_prp_pi(void* pms)
{
	ms_generate_prp_pi_t* ms = SGX_CAST(ms_generate_prp_pi_t*, pms);
	ms->ms_retval = generate_prp_pi(ms->ms_challenge);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_H(void* pms)
{
	ms_generate_H_t* ms = SGX_CAST(ms_generate_H_t*, pms);
	ms->ms_retval = generate_H(ms->ms_input, ms->ms_H_result_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_prf_f(void* pms)
{
	ms_generate_prf_f_t* ms = SGX_CAST(ms_generate_prf_f_t*, pms);
	ms->ms_retval = generate_prf_f(ms->ms_challenge, ms->ms_j, ms->ms_prf_result_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_prf_w(void* pms)
{
	ms_generate_prf_w_t* ms = SGX_CAST(ms_generate_prf_w_t*, pms);
	ms->ms_retval = generate_prf_w(ms->ms_key, ms->ms_index, ms->ms_prf_result_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_fdh_h(void* pms)
{
	ms_generate_fdh_h_t* ms = SGX_CAST(ms_generate_fdh_h_t*, pms);
	ms->ms_retval = generate_fdh_h(ms->ms_key, ms->ms_index_prf, ms->ms_index_prf_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pick_pdp_generator(void* pms)
{
	ms_pick_pdp_generator_t* ms = SGX_CAST(ms_pick_pdp_generator_t*, pms);
	ms->ms_retval = pick_pdp_generator(ms->ms_n);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_destroy_pdp_generator(void* pms)
{
	ms_destroy_pdp_generator_t* ms = SGX_CAST(ms_destroy_pdp_generator_t*, pms);
	destroy_pdp_generator(ms->ms_g);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_pdp_tag(void* pms)
{
	ms_generate_pdp_tag_t* ms = SGX_CAST(ms_generate_pdp_tag_t*, pms);
	ms->ms_retval = generate_pdp_tag();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_destroy_pdp_tag(void* pms)
{
	ms_destroy_pdp_tag_t* ms = SGX_CAST(ms_destroy_pdp_tag_t*, pms);
	destroy_pdp_tag(ms->ms_tag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_pdp_challenge(void* pms)
{
	ms_generate_pdp_challenge_t* ms = SGX_CAST(ms_generate_pdp_challenge_t*, pms);
	ms->ms_retval = generate_pdp_challenge();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_destroy_pdp_challenge(void* pms)
{
	ms_destroy_pdp_challenge_t* ms = SGX_CAST(ms_destroy_pdp_challenge_t*, pms);
	destroy_pdp_challenge(ms->ms_challenge);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_generate_pdp_proof(void* pms)
{
	ms_generate_pdp_proof_t* ms = SGX_CAST(ms_generate_pdp_proof_t*, pms);
	ms->ms_retval = generate_pdp_proof();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_destroy_pdp_proof(void* pms)
{
	ms_destroy_pdp_proof_t* ms = SGX_CAST(ms_destroy_pdp_proof_t*, pms);
	destroy_pdp_proof(ms->ms_proof);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[41];
} ocall_table_TestEnclave = {
	41,
	{
		(void*)TestEnclave_uprint,
		(void*)TestEnclave_pdp_tag_file,
		(void*)TestEnclave_pdp_challenge_file,
		(void*)TestEnclave_pdp_prove_file,
		(void*)TestEnclave_pdp_verify_file,
		(void*)TestEnclave_pdp_challenge_and_verify_file,
		(void*)TestEnclave_read_pdp_tag,
		(void*)TestEnclave_pdp_tag_block,
		(void*)TestEnclave_pdp_challenge,
		(void*)TestEnclave_pdp_generate_proof_update,
		(void*)TestEnclave_pdp_generate_proof_final,
		(void*)TestEnclave_pdp_verify_proof,
		(void*)TestEnclave_pdp_create_new_keypair,
		(void*)TestEnclave_pdp_get_keypair,
		(void*)TestEnclave_pdp_get_pubkey,
		(void*)TestEnclave_generate_pdp_key,
		(void*)TestEnclave_destroy_pdp_key,
		(void*)TestEnclave_sfree,
		(void*)TestEnclave_sanitize_pdp_challenge,
		(void*)TestEnclave_generate_prp_pi,
		(void*)TestEnclave_generate_H,
		(void*)TestEnclave_generate_prf_f,
		(void*)TestEnclave_generate_prf_w,
		(void*)TestEnclave_generate_fdh_h,
		(void*)TestEnclave_pick_pdp_generator,
		(void*)TestEnclave_destroy_pdp_generator,
		(void*)TestEnclave_generate_pdp_tag,
		(void*)TestEnclave_destroy_pdp_tag,
		(void*)TestEnclave_generate_pdp_challenge,
		(void*)TestEnclave_destroy_pdp_challenge,
		(void*)TestEnclave_generate_pdp_proof,
		(void*)TestEnclave_destroy_pdp_proof,
		(void*)TestEnclave_u_sgxssl_ftime,
		(void*)TestEnclave_sgx_oc_cpuidex,
		(void*)TestEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)TestEnclave_pthread_wait_timeout_ocall,
		(void*)TestEnclave_pthread_create_ocall,
		(void*)TestEnclave_pthread_wakeup_ocall,
	}
};
sgx_status_t test(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_TestEnclave, NULL);
	return status;
}

sgx_status_t ecall_verify(sgx_enclave_id_t eid, char** optarg, long int st_size)
{
	sgx_status_t status;
	ms_ecall_verify_t ms;
	ms.ms_optarg = optarg;
	ms.ms_st_size = st_size;
	status = sgx_ecall(eid, 1, &ocall_table_TestEnclave, &ms);
	return status;
}

