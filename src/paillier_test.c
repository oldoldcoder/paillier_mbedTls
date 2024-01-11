#include "paillier.h"

#include <mbedtls/bignum.h>
#include <mbedtls/platform.h>
#include <mbedtls/config.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include<stdio.h>
#include <string.h>


#define KEY_LEN 64
#define MAX_M_BITS 22

#define MAX_SUB_LEN MAX_M_BITS
#define SUB_CORRECTION_FACTOR MAX_M_BITS + 1

#define MAX_MULT_FACTOR_LEN KEY_LEN - MAX_M_BITS - 1



int main(){
    
    // useage is show middle value
    char buf[4000]; // assuse buffer is very large
    size_t olen;
    /*-----------*/
    paillierKeys keys;
    mbedtls_mpi res, m1, cm1,
        m2, cm2,
        r1, cr1,
        r2, cr2,
        correction_factor;
    mbedtls_mpi_init(&m1);
    mbedtls_mpi_init(&m2);
    mbedtls_mpi_init(&r1);
    mbedtls_mpi_init(&r2);
    mbedtls_mpi_init(&cm1);
    mbedtls_mpi_init(&cm2);
    mbedtls_mpi_init(&cr1);
    mbedtls_mpi_init(&cr2);
    mbedtls_mpi_init(&res);
    mbedtls_mpi_init(&correction_factor);
    mbedtls_mpi_lset(&m1,1111);
    
    mbedtls_mpi_lset(&m2,2222);
    
    mbedtls_mpi_lset(&r1,1234);
    
    mbedtls_mpi_lset(&r2,4321);
    // Generate Key
    generateRandomKeys(&keys,NULL);
    mbedtls_mpi_write_string(&m1, 10, buf, sizeof(buf), &olen);
    printf("orignal m1 value is: %s\n", buf);
    mbedtls_mpi_write_string(keys.pub.n, 10, buf, sizeof(buf), &olen);
    printf("orignal g value is: %s\n", buf);
    // 加密m1值 Encrypt m1 value
    encrypt(&cm1, &m1, &keys.pub);
    mbedtls_mpi_write_string(&cm1, 10, buf, sizeof(buf), &olen);
    printf("encrypt value: %s\n", buf);

    // 解密m1的值 Decrypt the value of m1
    decrypt(&res, &cm1, &keys.priv);
    
    mbedtls_mpi_write_string(&res, 10, buf, sizeof(buf), &olen);
    printf("encrypt value: %s\n", buf);

    if( mbedtls_mpi_cmp_mpi(&res,&m1) != 0)
        fprintf(stderr, "decrypt value after encrypt is not compare orignial value");

    /*-----计算加法-- Computational addition --*/
    // 密文加法 Ciphertext addition
    encrypt(&cm2,&m2,&keys.pub);
    enc_mpi_add(&res, &cm2, &cm1, &keys);
    decrypt(&res, &res, &keys.priv);
    
    mbedtls_mpi_write_string(&res, 10, buf, sizeof(buf), &olen);
    printf("m1 add m2 value: %s\n", buf);

    // 明密文加法 Plaintext addition
    encPlain_mpi_add(&res,&cm1,&r1,&keys);
    decrypt(&res, &res, &keys.priv);
    
    mbedtls_mpi_write_string(&res, 10, buf, sizeof(buf), &olen);
    printf("m1 add r1 value: %s\n", buf);

    /*----计算减法-- Calculate subtraction --*/
    // 大减小 Major reduction
    enc_mpi_sub(&res,&cm2,&cm1,&keys);
    decrypt(&res, &res, &keys.priv);
    
    mbedtls_mpi_write_string(&res, 10, buf, sizeof(buf), &olen);
    printf("m2 sub m1 value: %s\n", buf);
    // 小减大 Small decrease large,it should show a error answer
    enc_mpi_sub(&res,&cm1,&cm2,&keys);
    decrypt(&res, &res, &keys.priv);
    
    mbedtls_mpi_write_string(&res, 10, buf, sizeof(buf), &olen);
    printf("m1 sub m2 value: %s\n", buf);
    // 大减小利用修正因子 Significant reduction in utilization correction factor
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "my_entropy_context";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));

    mbedtls_mpi_fill_random(&correction_factor, 64, mbedtls_ctr_drbg_random, &ctr_drbg);

    enc_mpi_sub(&res, &cm2, &cm1, &keys);
    encPlain_mpi_add(&res,&res,&correction_factor,&keys);
    decrypt(&res, &res, &keys.priv);
    mbedtls_mpi_sub_mpi(&res, &res, &correction_factor);
    mbedtls_mpi_write_string(&res, 10, buf, sizeof(buf), &olen);
    printf("m2 sub m1 value(using correction_factor): %s\n", buf);
    // 小减大利用修正因子 Minor reduction and major utilization correction factor
    mbedtls_mpi_fill_random(&correction_factor, 64, mbedtls_ctr_drbg_random, &ctr_drbg);

    enc_mpi_sub(&res, &cm1, &cm2, &keys);
    encPlain_mpi_add(&res,&res,&correction_factor,&keys);
    decrypt(&res, &res, &keys.priv);
    mbedtls_mpi_sub_mpi(&res, &res, &correction_factor);
    mbedtls_mpi_write_string(&res, 10, buf, sizeof(buf), &olen);
    printf("m1 sub m2 value(using correction_factor): %s\n", buf);

    /*----标量乘法--scalar multiplication --*/
    mpi_mul_plain(&res,&cm1,&r1,&keys);
    decrypt(&res, &res, &keys.priv);
    mbedtls_mpi_write_string(&res, 10, buf, sizeof(buf), &olen);
    printf("m1 mul m2 value: %s\n", buf);
}