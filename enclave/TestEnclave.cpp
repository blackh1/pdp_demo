/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>

#include "TestEnclave.h"
#include "TestEnclave_t.h"  /* print_string */
#include "pdp.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define ADD_ENTROPY_SIZE	32

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

void test(){
	printf("test\n");
}

void ecall_verify(char **optarg,long st_size){
	/* Calculate the number pdp blocks in the file */
    unsigned int numfileblocks = 0;
    PDP_challenge *challenge = NULL, *server_challenge = NULL;
	PDP_proof *proof = NULL;
    PDP_key *key=NULL;
    numfileblocks = (st_size/PDP_BLOCKSIZE);
    if(st_size%PDP_BLOCKSIZE)
        numfileblocks++;

    pdp_challenge_file(&challenge,numfileblocks);
    if(!challenge) printf("No challenge\n");
    pdp_get_pubkey(&key);
    sanitize_pdp_challenge(&server_challenge,challenge);
    pdp_prove_file(&proof,*optarg, strlen(*optarg), NULL, 0, server_challenge, key);
    if(!proof) printf("No proof\n");
    int flag=0;
    pdp_verify_file(&flag,challenge,proof);
    if(flag)
        printf("Verified!\n");
    else
        printf("Cheating!\n");

    destroy_pdp_challenge(challenge);
    destroy_pdp_challenge(server_challenge);
    destroy_pdp_proof(proof);
}