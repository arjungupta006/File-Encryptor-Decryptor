#ifndef FILECRYPT_H
#define FILECRYPT_H

int encrypt_file(const char *input_file, const char *output_file, const char *password);
int decrypt_file(const char *input_file, const char *output_file, const char *password);

#endif
