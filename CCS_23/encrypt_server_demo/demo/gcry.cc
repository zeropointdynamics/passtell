// gcry.hh
// Copyright (C) 2013  Vedant Kumar <vsk@berkeley.edu>, see ~/LICENSE_gcry.txt.
#include "gcry.hh"

#ifdef DEMO
    extern unsigned short* tempPtr;
#endif

void xerr(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

void gcrypt_init()
{
    /* Version check should be the very first call because it
       makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        xerr("gcrypt: library version mismatch");
    }

    gcry_error_t err = 0;

    /* We don't want to see any warnings, e.g. because we have not yet
       parsed program options which might be used to suppress such
       warnings. */
    err = gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
       process might still be running with increased privileges and that
       the secure memory has not been intialized.  */

    /* Allocate a pool of 16k secure memory.  This make the secure memory
       available and also drops privileges where needed.  */
    err |= gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
       a problem with the secure memory. */
    err |= gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    err |= gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (err) {
        xerr("gcrypt: failed initialization");
    }
}

size_t get_keypair_size(int nbits)
{
    size_t aes_blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128);

    // format overhead * {pub,priv}key (2 * bits)
    size_t keypair_nbits = 4 * (2 * nbits);

    size_t rem = keypair_nbits % aes_blklen;
    return (keypair_nbits + rem) / 8;
}

void get_aes_ctx(gcry_cipher_hd_t* aes_hd, char* pw)
{
    const size_t keylen = 16;
    unsigned char passwd_hash[keylen];
    // Bump up the stack frame size
    char passwd[4096];
#ifdef DEMO
    int i;
#endif

    // Do something with the garbage to avoid it getting removed
    strcpy(passwd, pw);
    if (strlen(passwd) > 1024)
        printf("Oversized password\n");
    // Get rid of newline if it exists
    if (passwd[strlen(passwd) - 1] == '\n')
        passwd[strlen(passwd) - 1] = '\0';

    // char* passwd = getpass("Keypair Password: ");
    size_t pass_len = passwd ? strlen(passwd) : 0;
    if (pass_len == 0) {
        xerr("getpass: not a valid password");
    }

    int err = gcry_cipher_open(aes_hd, GCRY_CIPHER_IDEA, 
                               GCRY_CIPHER_MODE_CFB, 0);
    if (err) {
        xerr("gcrypt: failed to create aes handle");
    }

    gcry_md_hash_buffer(GCRY_MD_MD5, (void*) &passwd_hash, 
                        (const void*) passwd, pass_len);

    err = gcry_cipher_setkey(*aes_hd, (const void*) &passwd_hash, keylen);
    if (err) {
        xerr("gcrypt: could not set cipher key");
    }

#ifdef DEMO
    printf("\nReading address %p in user code after libgcrypt function returns:\n", tempPtr);
    for (i = 0; i < 52; i++) {
        printf("%04x ", tempPtr[i]);
    }
    printf("\n");
#endif

    err = gcry_cipher_setiv(*aes_hd, (const void*) &passwd_hash, 8);
    if (err) {
        xerr("gcrypt: could not set cipher initialization vector");
    }
}
