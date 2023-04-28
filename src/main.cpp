#include <cstdio>
#include <des.h>

#include "weak_keys.h"

void print_sub_keys(DES &cipher, FILE *output_file)
{
    fprintf_s(output_file, "Sub-keys:\n");
    for (uint8_t i = 0; i < 16; i+=2)
    {
        fprintf_s(output_file, "%d) %#llx\t%d) %#llx\n", i + 1, cipher.sub_key[i], i + 2, cipher.sub_key[i + 1]);
    }
    fprintf_s(output_file, "\n");
}

void simulate_semi_weak_keys(uint64_t plaintext, FILE *output_file)
{
    fprintf_s(output_file, "////////////////////////////////////////\nTesting out semi-weak keys!\n////////////////////////////////////////\n\n");

    for(uint8_t i = 0; i < NUM_SEMI_WEAK_KEY_PAIRS; i++)
    {
        uint64_t key_1 = semi_weak_key_1[i];
        uint64_t key_2 = semi_weak_key_2[i];

        DES cipher(key_1);

        fprintf_s(output_file, "Plaintext: \t\t%#llx\n", plaintext);

        fprintf_s(output_file, "Encryption key 1:\t%#llx\n", key_1);
        print_sub_keys(cipher, output_file);

        uint64_t ciphertext = DES::encrypt(plaintext, key_1);
        fprintf_s(output_file, "Ciphertext (w/ EK1):\t%#llx\n\n", ciphertext);

        fprintf_s(output_file, "Encryption key 2:\t%#llx\n", key_2);
        print_sub_keys(cipher, output_file);

        uint64_t encrypted_ciphertext = DES::encrypt(ciphertext, key_2);
        fprintf_s(output_file, "Encrypted ciphertext (w/ EK2):\t%#llx\n", encrypted_ciphertext);

        uint64_t decrypted_plaintext = DES::decrypt(ciphertext, key_1);
        fprintf_s(output_file, "Decrypted ciphertext:\t\t%#llx\n", decrypted_plaintext);
        fprintf_s(output_file, "----------------------------------------\n\n");
    }
}

void simulate_weak_keys(uint64_t plaintext, FILE *output_file)
{
    fprintf_s(output_file, "////////////////////////////////////////\nTesting out weak keys!\n////////////////////////////////////////\n\n");

    for(uint64_t key : weak_keys)
    {
        DES cipher(key);

        fprintf_s(output_file, "Initial 64-bit key supplied:\t%#llx\n", key);
        print_sub_keys(cipher, output_file);

        fprintf_s(output_file, "Plaintext: \t\t%#llx\n", plaintext);

        uint64_t ciphertext = DES::encrypt(plaintext, key);
        fprintf_s(output_file, "Ciphertext:\t\t%#llx\n", ciphertext);

        uint64_t encrypted_ciphertext = DES::encrypt(ciphertext, key);
        fprintf_s(output_file, "Encrypted ciphertext:\t%#llx\n", encrypted_ciphertext);

        uint64_t decrypted_plaintext = DES::decrypt(ciphertext, key);
        fprintf_s(output_file, "Decrypted ciphertext:\t%#llx\n", decrypted_plaintext);
        fprintf_s(output_file, "----------------------------------------\n\n");
    }
}

int main()
{
    FILE *weak_keys_file = nullptr;
    fopen_s(&weak_keys_file, "weak_keys.txt", "w");
    if(weak_keys_file == nullptr)
    {
        printf("Failed to open output file!\n");
        return -1;
    }

    FILE *semi_weak_keys_file = nullptr;
    fopen_s(&semi_weak_keys_file, "semi_weak_keys.txt", "w");
    if(semi_weak_keys_file == nullptr)
    {
        printf("Failed to open output file!\n");
        return -1;
    }

    uint64_t plaintext = 0xAAAAAAAAAAAAAAAA;
    printf("Enter your desired 64bit input in hex (Default: 0xAAAAAAAAAAAAAAAA): ");
    auto result = scanf_s("%llx", &plaintext);
    if(result == 0)
    {
        printf("Failed to read user input; plaintext will not change value!\n");
    }

    simulate_weak_keys(plaintext, weak_keys_file);
    simulate_weak_keys(plaintext, stdout);
    fclose(weak_keys_file);

    simulate_semi_weak_keys(plaintext, semi_weak_keys_file);
    simulate_semi_weak_keys(plaintext, stdout);
    fclose(semi_weak_keys_file);

    return 0;
}