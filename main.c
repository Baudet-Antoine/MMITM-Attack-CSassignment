#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

typedef struct {
    char *cipher;
    char *plain;
}C_P;

typedef struct {
    unsigned char MD5[16];
    char password[100];
} Password;

typedef struct Hash {
    char *key;
    size_t lenght;
    char *password;
    struct Hash *next;
}Hash;

typedef struct {
    Hash **buckets;
    size_t size;
}HashTable;

Password* readPasswordFile(char *fileName,int *count) {
    FILE *file = fopen(fileName,"r");

    Password *passwords = malloc(200000 * sizeof(Password));
    *count = 0;

    char line[200];
    while (fgets(line, sizeof(line), file)) {
        char hex[33];
        char password[100];

        if (sscanf(line, "%32s %99s", hex, password)) {
            for (int i = 0 ; i < 16 ; i++) {
                sscanf(hex + 2*i, "%2hhx", &passwords[*count].MD5[i]);
            }

            strcpy(passwords[*count].password, password);
            (*count)++;
        }
    }

    fclose(file);
    return passwords;
}

HashTable* createHashTable(size_t size) {
    HashTable *table = malloc(sizeof(HashTable));
    table->size = size;
    table->buckets = calloc(size, sizeof(Hash*));
    return table;
}

C_P getCP(char* inputFileName) {

    FILE *fpIn = fopen(inputFileName, "r");
    if(fpIn == NULL) {
        printf("File {%s} not found ",inputFileName);
    }

    fseek (fpIn, 0, SEEK_END);
    long lenght = ftell (fpIn);
    fseek (fpIn, 0, SEEK_SET);
    char * input = malloc(lenght + 1);
    fread (input, 1, lenght, fpIn);
    fclose (fpIn);


    size_t plainlenght = strchr(input,'\n') - input;
    char *plainText = malloc(plainlenght + 1);
    strncpy(plainText, input, plainlenght);
    plainText[plainlenght] = '\0';


    size_t cipherlenght = lenght - plainlenght - 1;
    char *cipherText = malloc(cipherlenght + 1);
    strncpy(cipherText, strchr(input, '\n') + 1, cipherlenght);
    cipherText[cipherlenght] = '\0';

    C_P cp = {cipherText,plainText};
    free(input);
    return cp;
}

int hashFunction(char *data, size_t lenght, size_t table_size) {
    int hash = 1234567;

    for (size_t i = 0 ; i < lenght ; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }

    return hash % table_size;
}

void InsertHashTable(HashTable *table, char *key, size_t lenght, char *password) {
    int i = hashFunction(key, lenght, table->size);

    Hash *hash = malloc(sizeof(Hash));

    hash->key = malloc(lenght);
    memcpy(hash->key, key, lenght);
    hash->lenght = lenght;

    hash->password = malloc(strlen(password)+1);
    strcpy(hash->password, password);

    hash->next = table->buckets[i];
    table->buckets[i] = hash;
}

char* SearchHashTable(HashTable *table, char *key, size_t lenght) {
    int index = hashFunction(key, lenght, table->size);

    Hash *hash = table->buckets[index];
    while (hash) {
        if (hash->lenght == lenght && memcmp(hash->key, key, lenght) == 0) {
            return hash->password;
        }
        hash = hash->next;
    }
    return NULL;
}


size_t base64_decode(const char* encoded_data, unsigned char** output) {
    BIO *bio, *b64;
    size_t input_length = strlen(encoded_data);
    size_t estimated_length = (input_length * 3) / 4;

    *output = (unsigned char*)malloc(estimated_length);
    if (*output == NULL) return 0;

    bio = BIO_new_mem_buf(encoded_data, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines

    size_t decoded_length = BIO_read(bio, *output, input_length);
    BIO_free_all(bio);

    return decoded_length;
}

unsigned char* des_ecb_encrypt(unsigned char* plaintext, size_t length, unsigned char* key) {
    DES_key_schedule schedule;
    DES_cblock key_block;

    memcpy(&key_block, key, 8);
    DES_set_key(&key_block, &schedule);

    unsigned char* ciphertext = malloc(length);

    // Encrypt in 8-byte blocks
    for (size_t i = 0; i < length; i += 8) {
        DES_ecb_encrypt((DES_cblock*)(plaintext + i),
                        (DES_cblock*)(ciphertext + i),
                        &schedule,
                        DES_ENCRYPT);
    }

    return ciphertext;
}

unsigned char* aes_cbc_decrypt(unsigned char* ciphertext, size_t length,
                                unsigned char* key, unsigned char* iv) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);

    unsigned char* plaintext = malloc(length);
    unsigned char iv_copy[16];
    memcpy(iv_copy, iv, 16); // IV gets modified during decryption

    AES_cbc_encrypt(ciphertext, plaintext, length, &aes_key, iv_copy, AES_DECRYPT);

    return plaintext;
}


int main(void) {

    // Step 1 : Gather the correct ciphertext and plaintext in variables
    char inputFileName[1000] = "PlaintextCiphertext.txt";
    C_P CipherPlain = getCP(inputFileName);

    //Step 2 : Decode the ciphertext to base64
    unsigned char* decodedCipher;
    size_t cipherSize = base64_decode(CipherPlain.cipher,&decodedCipher);

    //Step : Process the password file
    int pwCount;
    Password *passwords = readPasswordFile("passwords.txt",&pwCount);

    //Step 4 : Pad plaintext with DES block size
    size_t plainSize = strlen(CipherPlain.plain);
    size_t paddedPlainSize = ((plainSize +7)/8)*8;
    unsigned char *paddedPlain = calloc(paddedPlainSize, 1);
    memcpy(paddedPlain,CipherPlain.plain,plainSize);

    //Step 5 : Create the hash table
    HashTable *table = createHashTable(1000000);

    //Step 6 : Attack forward
    for (int i = 0 ; i < pwCount ; i++) {
        unsigned char desKey[8];
        memcpy(desKey, passwords[i].MD5, 8);

        unsigned char *desEncrypt = des_ecb_encrypt(paddedPlain,paddedPlainSize, desKey);
        InsertHashTable(table, (char*)desEncrypt, paddedPlainSize,passwords[i].password);

        free(desEncrypt);
    }

    //Step 7 : Attack Backward

    unsigned char iv[16] = {0};
    char *foundP1 = NULL;
    char *foundP2 = NULL;

    for (int i = 0 ; i < pwCount; i++) {
        char aesKey[16];

        memcpy(aesKey, passwords[i].MD5, 16);

        char *aesDecrypted = aes_cbc_decrypt(decodedCipher,cipherSize, aesKey, iv);

        foundP1 = SearchHashTable(table, (char*)aesDecrypted, paddedPlainSize);
        if (foundP1) {
            foundP2 = passwords[i].password;
            break;
        }

        free(aesDecrypted);
    }

    if (foundP1 && foundP2) {
        FILE *output = fopen("keys.txt", "w");
        fprintf(output, "%s\n%s\n", foundP1, foundP2);
        fclose(output);
        printf("Keys found :) \n");
    } else {
        printf("Keys not found :(\n");
    }


    free(decodedCipher);
    free(paddedPlain);
    free(passwords);
    free(CipherPlain.cipher);
    free(CipherPlain.plain);

    return 0;
}