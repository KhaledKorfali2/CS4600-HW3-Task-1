#include <stdio.h>
#include <openssl/bn.h>

/* Function to print a BIGNUM variable in hexadecimal format */
void printBN(const char* msg, BIGNUM* a)
{
    char* number_str = BN_bn2hex(a);
    printf("%s %s", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    /*printf("Starting...\n");*/
    /* Generate the keys */
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* e = BN_new();

    /*Initilize values for p, q, and e*/
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");


    /* Create a BN_CTX object for use in the following calculations */
    BN_CTX* ctx = BN_CTX_new();

    /* Calculate the value of n as p*q */
    BIGNUM* n = BN_new();
    BN_mul(n, p, q, ctx);

    /* Calculate the value of phi(n) as (p-1)*(q-1) */
    BIGNUM* phi = BN_new();
    BN_sub(p, p, BN_value_one()); // p = p - 1
    BN_sub(q, q, BN_value_one()); // q = q - 1
    BN_mul(phi, p, q, ctx);       // phi = (p-1)*(q-1)

    /* Calculate the greatest common divisor of e and phi(n) */
    BIGNUM* x = BN_new();
    BIGNUM* gcd = BN_new();
    BN_gcd(gcd, e, phi, ctx);

    /* Check if e and phi(n) are coprime */
    if (!BN_is_one(gcd))
    {
        printf("Modular inverse of e does not exist.\n");
    }
    /* Calculate the modular inverse of e */
    else if (!BN_mod_inverse(x, e, phi, ctx)) {
        printf("Failed to calculate modular inverse of e.\n");
    }
    /* Calculate the private key d and print the result */
    else
    {
        /* Create a new BIGNUM variable to store the value of d */
        BIGNUM* d = BN_new();

        /* Calculate d as the modular inverse of e mod phi(n) */
        if (BN_is_negative(x))
        {
            BN_add(d, x, phi); // d = x + phi(n)
        }
        else
        {
            BN_copy(d, x);     // d = x
        }

        /* Print the value of d and n as the private key */
        printBN("Private key (d, n) in hexadecimal format: \n(", d);
        printBN(",\n", n);
        printf(")\n");

        /* Free memory used by BIGNUM variable d */
        BN_free(d);
    }



    /* Free the memory*/
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(n);
    BN_free(phi);
    BN_free(x);
    BN_free(gcd);
    BN_CTX_free(ctx);

    /*Indicate the end of the program*/
    /*printf("End of program\n");*/
    return 0;
}
