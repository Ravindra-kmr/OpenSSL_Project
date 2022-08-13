/*
* Author: Ravindra kumar
* Last Modified: 13-Feb-2022
* Bugs: None
* Specification:
* * Operations: ENC, DEC
* * MODES: ECB, CBC
* * ALGO:  AES, 3DES
* * KeySize: AES(128,192,256), 3DES(168) bits
* * Will take a passphrase from user and expand it using sha1 message digest to required length to fill key and IV.
* * Genertes random salt and append it to the intial of generated encrypted file and can extract the same while decrypting.
* * Can decrypt a file generated using openssl command with command: openssl enc <algo> -e -in test1.dat -out test1openssl.enc -md sha1
* * Data Encrypted and decrypted using this program matches.
* * Can change the bufferSize as needed to define the number of bytes encrypted in one EVP function call.
* TODO:
* Check why: Encryted data from openssl command and encryption using this program doesnot match: openssl enc <algo> -e -in test1.dat -out test1openssl.enc -md sha1 -nosalt
*/

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <time.h>

#define bufferSize 1024

using namespace std;
const EVP_CIPHER * setup(bool algo, bool mode,unsigned int keysize);
void crypto_operation(const EVP_CIPHER *cipher, bool encrypt, char *in_file, char *out_file);
int main(int argc, char **argv)
{
    unsigned int keysize=0;
    bool mode;
    bool operation;
    bool algo;
    char *in_file, *out_file;
    const EVP_CIPHER *cipher;
    int option;

    while((option = getopt(argc,argv,"p:a:m:k:i:o:")) != -1){
        switch(option){
            case 'p':
                if(strcasecmp(optarg,"enc") || strcasecmp(optarg,"dec"))
                    operation = strcasecmp(optarg,"enc")? 0:1;
                else
                    printf("Please enter correct operation. Assuming enc.\n");
                break;
            case 'a':
                if(strcasecmp(optarg,"3DES") || strcasecmp(optarg,"AES"))
                    algo = strcasecmp(optarg,"AES")?0:1;
                else
                    printf("Please enter correct algorithm. Assuming AES.\n");
                break;
            case 'm':
                if(strcasecmp(optarg,"ECB") || strcasecmp(optarg,"CBC"))
                    mode = strcasecmp(optarg,"CBC")?0:1;
                else
                    printf("Please enter correct operation. Assuming CBC.\n");
                break;
            case 'k':
                keysize = (unsigned int)atoi(optarg);
                break;
            case 'i':
                in_file = optarg;
                break;
            case 'o':
                out_file = optarg;
                break;
            case '?':
                printf("Unknown option -%c\n",optopt);
                break;
            default:
                printf("Usage: %s -p <oper> -a <alg> -m <mode> -k <keysize> -i <inpfile> -o <outfile>.\n",argv[0]);
                return(1);
        }
    }
    cipher = setup(algo,mode,keysize);
    crypto_operation(cipher,operation,in_file,out_file);
    printf("***********************DONE***********************\n\n");
    return 0;
}

const EVP_CIPHER * setup(bool algo, bool mode,unsigned int keysize){
    const EVP_CIPHER *cipher;
    if(algo){	//aes
        if(mode){	//cbc
            if(keysize == 128){
                cipher = EVP_aes_128_cbc();
            }

            else if(keysize == 192){
                cipher = EVP_aes_192_cbc();
            }
            else if(keysize == 256){
                cipher = EVP_aes_256_cbc();
            }
            else{
                printf("Unknown keysize %d.\n",keysize);
                exit(1);
            }
        }
        else{
            if(keysize == 128){
                cipher = EVP_aes_128_ecb();
            }

            else if(keysize == 192){
                cipher = EVP_aes_192_ecb();
            }
            else if(keysize == 256){
                cipher = EVP_aes_256_ecb();
            }
            else{
                printf("Unknown keysize %d.\n",keysize);
                exit(1);
            }
        }
    }
    else{	//des
        if(mode){	//cbc
            if(keysize == 168){
                cipher = EVP_des_ede3_cbc();
            }
            else{
                printf("Unknown keysize %d.\n",keysize);
                exit(1);
            }
        }
        else{	//ecb
            if(keysize == 168){
                cipher = EVP_des_ede3_ecb();
            }
            else{
                printf("Unknown keysize %d.\n",keysize);
                exit(1);
            }
        }
    }
    return cipher;
}

void crypto_operation(const EVP_CIPHER *cipher, bool encrypt, char *in_file, char *out_file){
    EVP_CIPHER_CTX *ctx;
    struct timespec start, end;
    int bytesRead = 0, bytesWritten = 0;
    long counter = 0;
    unsigned char *input, *output ;
    int key_len = EVP_CIPHER_get_key_length(cipher);
    int iv_len = EVP_CIPHER_get_iv_length(cipher);
    int block_size = EVP_CIPHER_get_block_size(cipher);
    string passphrase;
    unsigned char salt[8] = {0};
    unsigned char *key = (unsigned char *)calloc(key_len,sizeof(unsigned char));
    unsigned char *iv= (unsigned char *)calloc(iv_len,sizeof(unsigned char));
    input = (unsigned char *)calloc(bufferSize , sizeof(unsigned char));
    output = (unsigned char *)calloc(bufferSize+EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));

    ERR_load_crypto_strings();

    FILE *infp = fopen(in_file,"rb");
    FILE *outfp = fopen(out_file,"wb");
    if(infp == NULL || outfp == NULL){
        cout << "Error while handling file operation.\n";
        exit(1);
    }
    if(encrypt){
        srand (time(NULL));
        salt[0] = rand()%0x100000000;
        salt[4] = rand()%0x100000000;
        fwrite("Salted__",sizeof(unsigned char),8,outfp);
        fwrite(salt,sizeof(unsigned char),8,outfp);
    }
    else{
        fread(output,sizeof(unsigned char),16,infp);
        if (strncmp((const char*)output,"Salted__",8) == 0) {
            memcpy(salt,&output[8],8);
          }
        else {
            fseek(infp,0,SEEK_SET);
        }
    }
    printf("Please enter the passphrase: ");
    cin >> passphrase;

    if(!EVP_BytesToKey(cipher, EVP_sha1(), salt, (unsigned char *)passphrase.c_str(), (passphrase.length()), 1, key, iv)){
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if(!(ctx = EVP_CIPHER_CTX_new())){
        EVP_CIPHER_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if(1 != EVP_CipherInit_ex(ctx, cipher, NULL, key, iv,encrypt)){
        EVP_CIPHER_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);        //Wall time-> CLOCK_REALTIME
    while(true){
        bytesRead = fread(input, sizeof(unsigned char),bufferSize,infp);
        if(bytesRead <=0)
            break;
        if(!EVP_CipherUpdate(ctx, output, &bytesWritten, input, bytesRead)){
            EVP_CIPHER_CTX_free(ctx);
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        fwrite(output,sizeof(unsigned char),bytesWritten,outfp);
        counter++;
    }
    if(1 != EVP_CipherFinal_ex(ctx, output, &bytesWritten)){
        EVP_CIPHER_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    fwrite(output,sizeof(unsigned char),bytesWritten,outfp);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
    long seconds = end.tv_sec - start.tv_sec;
    long nanoseconds = end.tv_nsec - start.tv_nsec;

    printf("Time required is(in millisec): %lf\n",(seconds*1e3 + nanoseconds*1e-6));
    printf("Time required per block(in nanosec): %lf\n",((seconds*1e9 + nanoseconds)*block_size/(bufferSize*counter)));
    printf("\n");
    EVP_CIPHER_CTX_cleanup(ctx);
    fclose(infp);
    fclose(outfp);
}