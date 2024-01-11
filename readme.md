paillier-mbedTls
==========

Using mbedtls to complete the basic operations of the Paillier algorithm

- Generate Key
- Encryption
- Decryption
- Ciphertext addition
- Cryptographic addition
- Scalar multiplication

#### Linux下:

~~~shell
cd yourDir
gcc -o paillier paillier.c paillier_test.c -I/usr/include -lmbedtls -lmbedx509 -lmbedcrypto
./paillier
~~~

#### Respect！

Referenced the code of the project：https://github.com/GerardGarcia/paillier-c
Respect！
