#include "TestEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_test(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	test();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verify_t* ms = SGX_CAST(ms_ecall_verify_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char** _tmp_optarg = ms->ms_optarg;
	size_t _len_optarg = sizeof(char*);
	char** _in_optarg = NULL;

	CHECK_UNIQUE_POINTER(_tmp_optarg, _len_optarg);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_optarg != NULL && _len_optarg != 0) {
		if ( _len_optarg % sizeof(*_tmp_optarg) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_optarg = (char**)malloc(_len_optarg);
		if (_in_optarg == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_optarg, _len_optarg, _tmp_optarg, _len_optarg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_verify(_in_optarg, ms->ms_st_size);
	if (_in_optarg) {
		if (memcpy_s(_tmp_optarg, _len_optarg, _in_optarg, _len_optarg)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_optarg) free(_in_optarg);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_test, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_verify, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[41][2];
} g_dyn_entry_table = {
	41,
	{
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL uprint(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_uprint_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_uprint_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_uprint_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_uprint_t));
	ocalloc_size -= sizeof(ms_uprint_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_tag_file(int* retval, char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_tag_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_tag_file_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_tag_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_tag_file_t));
	ocalloc_size -= sizeof(ms_pdp_tag_file_t);

	ms->ms_filepath = filepath;
	ms->ms_filepath_len = filepath_len;
	ms->ms_tagfilepath = tagfilepath;
	ms->ms_tagfilepath_len = tagfilepath_len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_challenge_file(PDP_challenge** retval, unsigned int numfileblocks)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_challenge_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_challenge_file_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_challenge_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_challenge_file_t));
	ocalloc_size -= sizeof(ms_pdp_challenge_file_t);

	ms->ms_numfileblocks = numfileblocks;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_prove_file(PDP_proof** retval, char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len, PDP_challenge* challenge, PDP_key* key)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_prove_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_prove_file_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_prove_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_prove_file_t));
	ocalloc_size -= sizeof(ms_pdp_prove_file_t);

	ms->ms_filepath = filepath;
	ms->ms_filepath_len = filepath_len;
	ms->ms_tagfilepath = tagfilepath;
	ms->ms_tagfilepath_len = tagfilepath_len;
	ms->ms_challenge = challenge;
	ms->ms_key = key;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_verify_file(int* retval, PDP_challenge* challenge, PDP_proof* proof)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_verify_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_verify_file_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_verify_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_verify_file_t));
	ocalloc_size -= sizeof(ms_pdp_verify_file_t);

	ms->ms_challenge = challenge;
	ms->ms_proof = proof;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_challenge_and_verify_file(int* retval, char* filepath, size_t filepath_len, char* tagfilepath, size_t tagfilepath_len)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_challenge_and_verify_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_challenge_and_verify_file_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_challenge_and_verify_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_challenge_and_verify_file_t));
	ocalloc_size -= sizeof(ms_pdp_challenge_and_verify_file_t);

	ms->ms_filepath = filepath;
	ms->ms_filepath_len = filepath_len;
	ms->ms_tagfilepath = tagfilepath;
	ms->ms_tagfilepath_len = tagfilepath_len;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL read_pdp_tag(PDP_tag** retval, FILE* tagfile, unsigned int index)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_read_pdp_tag_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_read_pdp_tag_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_read_pdp_tag_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_read_pdp_tag_t));
	ocalloc_size -= sizeof(ms_read_pdp_tag_t);

	ms->ms_tagfile = tagfile;
	ms->ms_index = index;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_tag_block(PDP_tag** retval, PDP_key* key, unsigned char* block, size_t blocksize, unsigned int index)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_tag_block_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_tag_block_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_tag_block_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_tag_block_t));
	ocalloc_size -= sizeof(ms_pdp_tag_block_t);

	ms->ms_key = key;
	ms->ms_block = block;
	ms->ms_blocksize = blocksize;
	ms->ms_index = index;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_challenge(PDP_challenge** retval, PDP_key* key, unsigned int numfileblocks)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_challenge_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_challenge_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_challenge_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_challenge_t));
	ocalloc_size -= sizeof(ms_pdp_challenge_t);

	ms->ms_key = key;
	ms->ms_numfileblocks = numfileblocks;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_generate_proof_update(PDP_proof** retval, PDP_key* key, PDP_challenge* challenge, PDP_tag* tag, PDP_proof* proof, unsigned char* block, size_t blocksize, unsigned int j)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_generate_proof_update_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_generate_proof_update_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_generate_proof_update_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_generate_proof_update_t));
	ocalloc_size -= sizeof(ms_pdp_generate_proof_update_t);

	ms->ms_key = key;
	ms->ms_challenge = challenge;
	ms->ms_tag = tag;
	ms->ms_proof = proof;
	ms->ms_block = block;
	ms->ms_blocksize = blocksize;
	ms->ms_j = j;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_generate_proof_final(PDP_proof** retval, PDP_key* key, PDP_challenge* challenge, PDP_proof* proof)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_generate_proof_final_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_generate_proof_final_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_generate_proof_final_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_generate_proof_final_t));
	ocalloc_size -= sizeof(ms_pdp_generate_proof_final_t);

	ms->ms_key = key;
	ms->ms_challenge = challenge;
	ms->ms_proof = proof;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_verify_proof(int* retval, PDP_key* key, PDP_challenge* challenge, PDP_proof* proof)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_verify_proof_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_verify_proof_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_verify_proof_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_verify_proof_t));
	ocalloc_size -= sizeof(ms_pdp_verify_proof_t);

	ms->ms_key = key;
	ms->ms_challenge = challenge;
	ms->ms_proof = proof;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_create_new_keypair(PDP_key** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_create_new_keypair_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_create_new_keypair_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_create_new_keypair_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_create_new_keypair_t));
	ocalloc_size -= sizeof(ms_pdp_create_new_keypair_t);

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_get_keypair(PDP_key** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_get_keypair_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_get_keypair_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_get_keypair_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_get_keypair_t));
	ocalloc_size -= sizeof(ms_pdp_get_keypair_t);

	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pdp_get_pubkey(PDP_key** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pdp_get_pubkey_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pdp_get_pubkey_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pdp_get_pubkey_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pdp_get_pubkey_t));
	ocalloc_size -= sizeof(ms_pdp_get_pubkey_t);

	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_pdp_key(PDP_key** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_pdp_key_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_pdp_key_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_pdp_key_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_pdp_key_t));
	ocalloc_size -= sizeof(ms_generate_pdp_key_t);

	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL destroy_pdp_key(PDP_key* key)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_destroy_pdp_key_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_destroy_pdp_key_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_destroy_pdp_key_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_destroy_pdp_key_t));
	ocalloc_size -= sizeof(ms_destroy_pdp_key_t);

	ms->ms_key = key;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sfree(void* ptr, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sfree_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sfree_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sfree_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sfree_t));
	ocalloc_size -= sizeof(ms_sfree_t);

	ms->ms_ptr = ptr;
	ms->ms_size = size;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sanitize_pdp_challenge(PDP_challenge** retval, PDP_challenge* challenge)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sanitize_pdp_challenge_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sanitize_pdp_challenge_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sanitize_pdp_challenge_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sanitize_pdp_challenge_t));
	ocalloc_size -= sizeof(ms_sanitize_pdp_challenge_t);

	ms->ms_challenge = challenge;
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_prp_pi(unsigned int** retval, PDP_challenge* challenge)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_prp_pi_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_prp_pi_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_prp_pi_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_prp_pi_t));
	ocalloc_size -= sizeof(ms_generate_prp_pi_t);

	ms->ms_challenge = challenge;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_H(unsigned char** retval, BIGNUM* input, size_t* H_result_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_H_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_H_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_H_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_H_t));
	ocalloc_size -= sizeof(ms_generate_H_t);

	ms->ms_input = input;
	ms->ms_H_result_size = H_result_size;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_prf_f(unsigned char** retval, PDP_challenge* challenge, unsigned int j, size_t* prf_result_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_prf_f_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_prf_f_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_prf_f_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_prf_f_t));
	ocalloc_size -= sizeof(ms_generate_prf_f_t);

	ms->ms_challenge = challenge;
	ms->ms_j = j;
	ms->ms_prf_result_size = prf_result_size;
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_prf_w(unsigned char** retval, PDP_key* key, unsigned int index, size_t* prf_result_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_prf_w_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_prf_w_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_prf_w_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_prf_w_t));
	ocalloc_size -= sizeof(ms_generate_prf_w_t);

	ms->ms_key = key;
	ms->ms_index = index;
	ms->ms_prf_result_size = prf_result_size;
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_fdh_h(BIGNUM** retval, PDP_key* key, unsigned char* index_prf, size_t index_prf_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_fdh_h_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_fdh_h_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_fdh_h_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_fdh_h_t));
	ocalloc_size -= sizeof(ms_generate_fdh_h_t);

	ms->ms_key = key;
	ms->ms_index_prf = index_prf;
	ms->ms_index_prf_size = index_prf_size;
	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pick_pdp_generator(PDP_generator** retval, BIGNUM* n)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pick_pdp_generator_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pick_pdp_generator_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pick_pdp_generator_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pick_pdp_generator_t));
	ocalloc_size -= sizeof(ms_pick_pdp_generator_t);

	ms->ms_n = n;
	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL destroy_pdp_generator(PDP_generator* g)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_destroy_pdp_generator_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_destroy_pdp_generator_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_destroy_pdp_generator_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_destroy_pdp_generator_t));
	ocalloc_size -= sizeof(ms_destroy_pdp_generator_t);

	ms->ms_g = g;
	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_pdp_tag(PDP_tag** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_pdp_tag_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_pdp_tag_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_pdp_tag_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_pdp_tag_t));
	ocalloc_size -= sizeof(ms_generate_pdp_tag_t);

	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL destroy_pdp_tag(PDP_tag* tag)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_destroy_pdp_tag_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_destroy_pdp_tag_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_destroy_pdp_tag_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_destroy_pdp_tag_t));
	ocalloc_size -= sizeof(ms_destroy_pdp_tag_t);

	ms->ms_tag = tag;
	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_pdp_challenge(PDP_challenge** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_pdp_challenge_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_pdp_challenge_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_pdp_challenge_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_pdp_challenge_t));
	ocalloc_size -= sizeof(ms_generate_pdp_challenge_t);

	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL destroy_pdp_challenge(PDP_challenge* challenge)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_destroy_pdp_challenge_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_destroy_pdp_challenge_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_destroy_pdp_challenge_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_destroy_pdp_challenge_t));
	ocalloc_size -= sizeof(ms_destroy_pdp_challenge_t);

	ms->ms_challenge = challenge;
	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL generate_pdp_proof(PDP_proof** retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_generate_pdp_proof_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_generate_pdp_proof_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_generate_pdp_proof_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_generate_pdp_proof_t));
	ocalloc_size -= sizeof(ms_generate_pdp_proof_t);

	status = sgx_ocall(30, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL destroy_pdp_proof(PDP_proof* proof)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_destroy_pdp_proof_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_destroy_pdp_proof_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_destroy_pdp_proof_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_destroy_pdp_proof_t));
	ocalloc_size -= sizeof(ms_destroy_pdp_proof_t);

	ms->ms_proof = proof;
	status = sgx_ocall(31, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(33, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(34, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(35, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(36, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(37, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_timeout = timeout;
	status = sgx_ocall(38, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(39, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(40, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

