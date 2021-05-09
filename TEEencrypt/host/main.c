/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>
/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)
#define LEN 100

void rsa_gen_keys(TEEC_Session *sess) {
	TEEC_Result res;
	res = TEEC_InvokeCommand(sess, TA_RSA_GET, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GET) failed %#x\n", res);
	printf("\n=== Keys generated ===\n");
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t origin;
	char plaintext[LEN] = {0,};
	char ciphertext[LEN] = {0,};
	char key[LEN]={0,};
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res)
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",res, origin);
	if(argc > 5 || argc == 0){
		printf("Out of statement.\n");
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		return 1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = LEN;

	if(!strcmp("-e", argv[1])){
		FILE* fa;
		fa = fopen(argv[2], "r");
		fread(plaintext, sizeof(plaintext), 1, fa);
		fclose(fa);
		memcpy(op.params[0].tmpref.buffer, plaintext, LEN);
		char *cipher = NULL;
		TEEC_Result result;
		printf("=====PlainText======\n%s \n",plaintext);
		if(!strcmp(argv[3], "RSA")){
			op.params[2].tmpref.buffer = clear;
			op.params[2].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
			op.params[3].tmpref.buffer = ciph;
			op.params[3].tmpref.size = RSA_CIPHER_LEN_1024;

			rsa_gen_keys(&sess);
			result = TEEC_InvokeCommand(&sess, TA_RSA_ENC, &op, &origin);
			if (result != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_ENC) failed 0x%x origin 0x%x\n", result, origin);
			cipher = ciph;
		
		}else if(!strcmp(argv[3], "Caesar")){	
			result = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &origin);
			if (result != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", result, origin);
			memcpy(ciphertext, op.params[0].tmpref.buffer, LEN);
			int keyvalue = op.params[1].value.a;
			char keynum[10]={0,};
			sprintf(keynum, "%d", keyvalue);
			FILE *fg = fopen("ciphertext_key.txt", "w");
			fwrite(keynum, strlen(keynum), 1, fg); 
			fclose(fg);
			cipher = ciphertext;
		}else{
			printf("Fail Argv.\n");
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);		
			return 1;
		}
		if(result == TEEC_SUCCESS){
			printf("=====Ciphertext=====\n%s", cipher);
			FILE *fb = fopen("ciphertext.txt", "w");
			fwrite(cipher, strlen(cipher), 1, fb); 
			fclose(fb);
			printf("\nSuccessfully Saved\n");
		}
	}
	else if(!strcmp("-d", argv[1])){
		FILE* fc = fopen(argv[2], "r");
		fread(ciphertext, sizeof(ciphertext), 1, fc);
		fclose(fc);
		memcpy(op.params[0].tmpref.buffer, ciphertext, LEN);
		char *plain = NULL;
		TEEC_Result result;
		printf("=====Ciphertext=====\n%s \n", ciphertext);
		if(!strcmp(argv[3], "RSA")){
			op.params[2].tmpref.buffer = ciph;
			op.params[2].tmpref.size = RSA_CIPHER_LEN_1024;
			op.params[3].tmpref.buffer = clear;
			op.params[3].tmpref.size = RSA_MAX_PLAIN_LEN_1024;

			rsa_gen_keys(&sess);
			result = TEEC_InvokeCommand(&sess, TA_RSA_DEC, &op, &origin);
			if (result != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_RSA_DEC) failed 0x%x origin 0x%x\n", result, origin);
			plain = ciph;
		}else if(!strcmp(argv[4], "Caesar")){	
			FILE* fe = fopen(argv[3], "r");
			fread(key, sizeof(key), 1, fe);
			fclose(fe);
			int value = atoi(key);
			printf("=====Key Value=====\n%d \n\n",value);
			op.params[1].value.a = value;

			result = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &origin);
			if (result != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", result, origin);
			memcpy(plaintext, op.params[0].tmpref.buffer, LEN);
			plain = plaintext;
		}else{
			printf("Fail Argv.\n");
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			return 1;
		}
		if(result == TEEC_SUCCESS){
			printf("=====Plaintext=====\n%s", plain);
			FILE *fd = fopen("plaintext_dec.txt", "w");
			fwrite(plain, strlen(plain), 1, fd); 
			fclose(fd);
		}
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}