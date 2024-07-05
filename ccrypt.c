#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define SALT_SIZE 16
#define KEY_SIZE 32
#define BLOCK_SIZE 16

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void generate_key_from_password(const char *password, unsigned char *salt, unsigned char *key) {
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 100000, EVP_sha256(), KEY_SIZE, key) == 0) {
        handle_errors();
    }
}

int encrypt_decrypt_file(const char *file_path, unsigned char *key, int do_encrypt) {
    FILE *in_file = fopen(file_path, "rb");
    FILE *out_file = fopen("temp_file", "wb");

    if (!in_file || !out_file) {
        perror("File opening failed");
        return 0;
    }

    unsigned char iv[BLOCK_SIZE];
    if (do_encrypt) {
        if (RAND_bytes(iv, BLOCK_SIZE) != 1) {
            handle_errors();
        }
        fwrite(iv, 1, BLOCK_SIZE, out_file);
    } else {
        fread(iv, 1, BLOCK_SIZE, in_file);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_errors();
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, do_encrypt) != 1) {
        handle_errors();
    }

    unsigned char in_buf[1024];
    unsigned char out_buf[1024 + BLOCK_SIZE];
    int in_len, out_len;
    int success = 1;

    while ((in_len = fread(in_buf, 1, 1024, in_file)) > 0) {
        if (EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, in_len) != 1) {
            success = 0;
            break;
        }
        fwrite(out_buf, 1, out_len, out_file);
    }

    if (success && EVP_CipherFinal_ex(ctx, out_buf, &out_len) != 1) {
        success = 0;
    }

    fwrite(out_buf, 1, out_len, out_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_file);
    fclose(out_file);

    if (success) {
        remove(file_path);
        rename("temp_file", file_path);
    } else {
        remove("temp_file");
    }

    return success;
}

void process_directory(const char *directory, const char *password, int do_encrypt) {
    struct dirent *entry;
    struct stat entry_info;
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    int decryption_successful = 1;

    if (do_encrypt) {
        if (RAND_bytes(salt, SALT_SIZE) != 1) {
            handle_errors();
        }
        char salt_file_path[512];
        snprintf(salt_file_path, sizeof(salt_file_path), "%s/salt.bin", directory);
        FILE *salt_file = fopen(salt_file_path, "wb");
        fwrite(salt, 1, SALT_SIZE, salt_file);
        fclose(salt_file);
    } else {
        char salt_file_path[512];
        snprintf(salt_file_path, sizeof(salt_file_path), "%s/salt.bin", directory);
        FILE *salt_file = fopen(salt_file_path, "rb");
        if (!salt_file) {
            printf("Salt file not found in '%s'. Cannot decrypt.\n", directory);
            return;
        }
        fread(salt, 1, SALT_SIZE, salt_file);
        fclose(salt_file);
    }

    generate_key_from_password(password, salt, key);

    DIR *dp = opendir(directory);
    if (!dp) {
        perror("Directory opening failed");
        return;
    }

    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);

        if (stat(path, &entry_info) == 0 && S_ISDIR(entry_info.st_mode)) {
            process_directory(path, password, do_encrypt);
        } else if (strcmp(entry->d_name, "salt.bin") != 0) {
            if (!encrypt_decrypt_file(path, key, do_encrypt)) {
                decryption_successful = 0;
            }
        }
    }

    closedir(dp);

    if (!do_encrypt && decryption_successful) {
        char salt_file_path[512];
        snprintf(salt_file_path, sizeof(salt_file_path), "%s/salt.bin", directory);
        if (remove(salt_file_path) != 0) {
            perror("Error deleting salt file");
        }
    }
}

int main() {
    char operation[10];
    char directory[512];
    char password[128];

    while (1) {
        printf("Enter operation (encrypt/decrypt/exit): ");
        scanf("%s", operation);

        if (strcmp(operation, "encrypt") == 0 || strcmp(operation, "decrypt") == 0) {
            int do_encrypt = (strcmp(operation, "encrypt") == 0);

            printf("Enter directory path: ");
            scanf("%s", directory);
            printf("Enter password: ");
            scanf("%s", password);

            process_directory(directory, password, do_encrypt);
        } else if (strcmp(operation, "exit") == 0) {
            break;
        } else {
            printf("Invalid operation. Try again.\n");
        }
    }

    return 0;
}
