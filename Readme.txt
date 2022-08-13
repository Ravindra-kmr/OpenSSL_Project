This project was done as part of coursework CS6500 (Network Security) taught by Prof. Krishna Moorthy Sivalingam at IITM. This project has 2 parts (q1 and q2).  
 
First part (q1) demonstrate use of OpenSSL libraries (libcrypto and libssl) in C++.

Second part (q2) demonstate the use of Brute force attack on simple encryption algorithm.

* All programs are working and there are no bugs.
* All the source code are present in src file.
* To compile and create executable of each programs.
RUN: $ make

* Note that first program depend on openssl 3.0 library (libcrypto.so.3) so I have included in the zip file. (Most probably shared library is architecture dependent, if it the case then you have to build openssl 3.0).

Question 1: Syntax
./bin/q1 -p <oper> -a <alg> -m <mode> -k <keysize> -i <inpfile> -o <outfile>

Then enter the passphrase to generate key and IV.

Question 2: Syntax
./bin/q2 <Encrypted_files_filename>

At the end RUN: make clean

