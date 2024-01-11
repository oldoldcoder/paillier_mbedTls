// 引入大数库
#include <mbedtls/bignum.h>
#include <mbedtls/platform.h>
#include <mbedtls/config.h>
#define DEFAULT_KEY_LEN 1024

typedef struct _pubKey
{
    mbedtls_mpi *n, *n2;
    mbedtls_mpi *g;
} pubKey;

typedef struct _privKey
{
    mbedtls_mpi *n, *n2;
    mbedtls_mpi *lamda, *mu;
} privKey;

typedef struct _paillierKeys
{
    struct _pubKey pub;
    struct _privKey priv;
} paillierKeys;

// 随机生成密钥
int generateRandomKeys(paillierKeys *keys, int *key_len);

// 加密
int encrypt(mbedtls_mpi *res,const mbedtls_mpi *plain, pubKey *pbkey);

// 解密
int decrypt(mbedtls_mpi *res,const mbedtls_mpi *c,privKey * pvkey);

// 密文加法
int enc_mpi_add(mbedtls_mpi *res, const mbedtls_mpi *a, const mbedtls_mpi *b, paillierKeys *keys);

// 密文减法
int enc_mpi_sub(mbedtls_mpi *res, const mbedtls_mpi *a, const mbedtls_mpi *b, paillierKeys *keys);

// 与明文乘法
int mpi_mul_plain(mbedtls_mpi *res, const mbedtls_mpi *a, const mbedtls_mpi *plain, paillierKeys *keys);

// 密文 + 明文乘法
int encPlain_mpi_add(mbedtls_mpi *res, const mbedtls_mpi *a, const mbedtls_mpi *Plain, paillierKeys *keys);