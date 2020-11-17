
The project demonstrates a novel user matching protocol using Intel SGX for social networks.


---------------------------------------------
How to Build
---------------------------------------------
1. Install Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux
2. Build OpenSSL for Intel SGX
3. Fix the dependencies in Makefile (mainly the path to OpenSSL)
4. Make

Credits to Sasy for the implementation of Oblivious Data Structure ZeroTrace [1].

[1]. Sasy, Sajin, Sergey Gorbunov, and Christopher W. Fletcher. "ZeroTrace: Oblivious Memory Primitives from Intel SGX." IACR Cryptol. ePrint Arch. 2017 (2017): 549.
