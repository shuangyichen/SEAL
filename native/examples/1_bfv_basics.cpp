// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <iostream>
#include <iomanip>
#include <fstream>

using namespace std;
using namespace seal;

/*
Both the BFV scheme (with BatchEncoder) as well as the CKKS scheme support native
vectorized computations on encrypted numbers. In addition to computing slot-wise,
it is possible to rotate the encrypted vectors cyclically.
*/
void example_bfv_basics()
{
    print_example_banner("Example: Common public key Encryption & Distribute decryption");

    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // vector<KeyGenerator> KeyGens(3);
    vector<SecretKey> SKS(3);
    vector<PublicKey> PKS(3);


    KeyGenerator keygen1(context);
    KeyGenerator keygen2(context);
    KeyGenerator keygen3(context);


    print_line(__LINE__);
    cout <<"Party 0 generating key pair"<< endl;
    SKS[0] = keygen1.secret_key();
    keygen1.create_public_key_crp(PKS[0]);
    print_line(__LINE__);
    cout <<"Party 1 generating key pair"<< endl;
    SKS[1] = keygen2.secret_key();
    keygen2.create_public_key_crp(PKS[1]);
    print_line(__LINE__);
    cout <<"Party 2 generating key pair"<< endl;
    SKS[2] = keygen3.secret_key();
    keygen3.create_public_key_crp(PKS[2]);



    PublicKey CPK;
    SecretKey CSK;
    KeyGenerator keygen(context);
    print_line(__LINE__);
    cout <<"Server aggregating public keys from clients to generate common public key"<< endl;
    keygen.create_common_public_key(CPK,PKS,3);
    keygen.create_common_secret_key(CSK,SKS,3);



 



 
    Encryptor encryptor(context, CPK);
    Evaluator evaluator(context);
    Decryptor decryptor(context, CSK);

    print_line(__LINE__);
    int x = 6;
    Plaintext x_plain(to_string(x));
    cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;
    print_line(__LINE__);
    Ciphertext x_encrypted;
    cout << "Encrypt x_plain to x_encrypted." << endl;
    encryptor.encrypt(x_plain, x_encrypted);
    Plaintext x_decrypted;
    cout << "    + distribute decryption of x_encrypted: ";
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;



    /*
    First we use BatchEncoder to encode the matrix into a plaintext. We encrypt
    the plaintext as usual.
    */

    /*
    We can also rotate the columns, i.e., swap the rows.
    */
    // print_line(__LINE__);
    // cout << "Rotate columns." << endl;
    // evaluator.rotate_columns_inplace(encrypted_matrix, galois_keys);
    // cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
    //      << endl;
    // cout << "    + Decrypt and decode ...... Correct." << endl;
    // decryptor.decrypt(encrypted_matrix, plain_result);
    // batch_encoder.decode(plain_result, pod_matrix);
    // print_matrix(pod_matrix, row_size);

    /*
    Finally, we rotate the rows 4 steps to the right, decrypt, decode, and print.
    */
    // print_line(__LINE__);
    // cout << "Rotate rows 4 steps right." << endl;
    // evaluator.rotate_rows_inplace(encrypted_matrix, -4, galois_keys);
    // cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
    //      << endl;
    // cout << "    + Decrypt and decode ...... Correct." << endl;
    // decryptor.decrypt(encrypted_matrix, plain_result);
    // batch_encoder.decode(plain_result, pod_matrix);
    // print_matrix(pod_matrix, row_size);

    /*
    Note that rotations do not consume any noise budget. However, this is only
    the case when the special prime is at least as large as the other primes. The
    same holds for relinearization. Microsoft SEAL does not require that the
    special prime is of any particular size, so ensuring this is the case is left
    for the user to do.
    */
}



// void example_rotation()
// {
//     // print_example_banner("Example: ");

//     /*
//     Run all rotation examples.
//     */
//     example_rotation_bfv();
//     // example_rotation_ckks();
// }
