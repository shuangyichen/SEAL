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
void example_rotation_bfv()
{
    print_example_banner("Example: Rotation / Rotation in BFV");

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
    vector<RelinKeys> RKS_round_one(3);
    
    vector<GaloisKeys> galois_keys_set(3);


    KeyGenerator keygen1(context);
    KeyGenerator keygen2(context);
    KeyGenerator keygen3(context);
    // for (int i = 0; i <3; ++i) {
    //     KeyGens[i](context);
    //     SKS[i] = KeyGens[i].secret_key();
    //     // PublicKey public_key;
    //     KeyGens[i].create_public_key_crp(PKS[i]);
    //     galois_keys_set[i] = KeyGens[i].create_galois_keys(galois_keys_set[i]);
    // }
    vector<int> steps(1,3);
    SKS[0] = keygen1.secret_key();
    keygen1.create_public_key_crp(PKS[0]);
    // keygen1.create_galois_keys_crp(steps,galois_keys_set[0]);
    keygen1.create_relin_keys_round_one(RKS_round_one[0]);
    // auto PK0 = keygen1.create_public_key_crp();
    // auto rotKey0 = keygen1.create_galois_keys_crp(steps);

    SKS[1] = keygen2.secret_key();
    // auto PK1 = keygen2.create_public_key_crp();
    // auto rotKey1 = keygen2.create_galois_keys_crp(steps);

    keygen2.create_public_key_crp(PKS[1]);
    // keygen2.create_galois_keys_crp(steps,galois_keys_set[1]);
    keygen2.create_relin_keys_round_one(RKS_round_one[1]);

    SKS[2] = keygen3.secret_key();
    keygen3.create_public_key_crp(PKS[2]);
    // auto PK2 = keygen3.create_public_key_crp();
    // auto rotKey2 = keygen3.create_galois_keys_crp(steps);
    // keygen3.create_galois_keys_crp(steps,galois_keys_set[2]);
    keygen3.create_relin_keys_round_one(RKS_round_one[2]);


    PublicKey CPK;
    SecretKey CSK;
    KeyGenerator keygen(context);
    // KeyGenerator keygen(context);
    keygen.create_common_public_key(CPK,PKS,3);
    keygen.create_common_secret_key(CSK,SKS,3);
    // rotKey0.save(pk_stream);
    // galois_keys_set[0].load(context,pk_stream);
    // rotKey1.save(pk_stream);
    // galois_keys_set[1].load(context,pk_stream);
    // rotKey2.save(pk_stream);
    // galois_keys_set[2].load(context,pk_stream);



    cout <<"Generate CPK, CSK"<< endl;
    // cout<< *CPK.data().data(1)<<endl;
    // cout<< *CPK.data().data()<<endl;

    // GaloisKeys cRotKeys;
    // keygen.gen_common_galois_keys(galois_keys_set,3,cRotKeys);
    // cout <<"Generate collective rotation key "<< endl;

    RelinKeys Relin_key_round_one;
    keygen.aggregate_relin_keys_round_one(Relin_key_round_one,RKS_round_one,3);
    cout <<"Aggregate Relin key share round one "<< endl;

    vector<RelinKeys> RKS_round_two(3);
    keygen1.create_relin_keys_round_two(RKS_round_two[0],Relin_key_round_one);
    keygen2.create_relin_keys_round_two(RKS_round_two[1],Relin_key_round_one);
    keygen3.create_relin_keys_round_two(RKS_round_two[2],Relin_key_round_one);
    cout <<"Generate Relin key share round two "<< endl;
    RelinKeys Relin_key_round_two;
    keygen.aggregate_relin_keys_round_two(Relin_key_round_two,Relin_key_round_one,RKS_round_two,3);
    cout <<"Aggregate Relin key share round two "<< endl;
    Encryptor encryptor(context, CPK);
    Evaluator evaluator(context);
    Decryptor decryptor0(context, SKS[0]);
    Decryptor decryptor1(context, SKS[1]);
    Decryptor decryptor2(context, SKS[2]);
    Decryptor decryptor(context,CSK);

    print_line(__LINE__);
    int x = 6;
    Plaintext x_plain(to_string(x));
    cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;
    print_line(__LINE__);
    Ciphertext x_encrypted;
    cout << "Encrypt x_plain to x_encrypted." << endl;
    encryptor.encrypt(x_plain, x_encrypted);
    Plaintext x_decrypted;
    cout << "    + decryption of x_encrypted: ";
    // vector<Ciphertext> Partial_Decryption(3);
    // cout << " DIstribute decryption    "<<endl;
    // vector<Ciphertext> Partial_Decryption(3);
    // decryptor0.distributed_decrypt(x_encrypted, Partial_Decryption[0]);
    // decryptor1.distributed_decrypt(x_encrypted, Partial_Decryption[1]);
    // decryptor2.distributed_decrypt(x_encrypted, Partial_Decryption[2]);
    // decryptor.aggregate_partial_decryption(x_encrypted,Partial_Decryption,x_decrypted,3);
    // cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;


    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext. We encrypt
    the plaintext as usual.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    evaluator.square_inplace(encrypted_matrix);
    evaluator.relinearize_inplace(encrypted_matrix, Relin_key_round_two);
    
    Plaintext plain_result0;
    vector<Ciphertext> Partial_Decryption(3);
    decryptor0.distributed_decrypt(encrypted_matrix, Partial_Decryption[0]);
    decryptor1.distributed_decrypt(encrypted_matrix, Partial_Decryption[1]);
    decryptor2.distributed_decrypt(encrypted_matrix, Partial_Decryption[2]);
    decryptor.aggregate_partial_decryption(encrypted_matrix,Partial_Decryption,plain_result0,3);
    batch_encoder.decode(plain_result0, pod_matrix);
    print_matrix(pod_matrix, row_size);
    /*
    Rotations require yet another type of special key called `Galois keys'. These
    are easily obtained from the KeyGenerator.
    */
    // GaloisKeys galois_keys = keygen.create_galois_keys(galois_keys);

    /*
    Now rotate both matrix rows 3 steps to the left, decrypt, decode, and print.
    */
    // print_line(__LINE__);
    // cout << "Rotate rows 3 steps left." << endl;
    // evaluator.rotate_rows_inplace(encrypted_matrix, 3, cRotKeys);
    // Plaintext plain_result;
    // cout << "    + Noise budget after rotation: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
    //      << endl;
    // cout << "    + Decrypt and decode ...... Correct." << endl;
    // decryptor.decrypt(encrypted_matrix, plain_result);
    // batch_encoder.decode(plain_result, pod_matrix);
    // print_matrix(pod_matrix, row_size);

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

void example_rotation_ckks()
{
    print_example_banner("Example: Rotation / Rotation in CKKS");

    /*
    Rotations in the CKKS scheme work very similarly to rotations in BFV.
    */
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 }));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector:" << endl;
    print_vector(input, 3, 7);

    auto scale = pow(2.0, 50);

    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    Plaintext plain;
    ckks_encoder.encode(input, scale, plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    Ciphertext rotated;
    print_line(__LINE__);
    cout << "Rotate 2 steps left." << endl;
    evaluator.rotate_vector(encrypted, 2, galois_keys, rotated);
    cout << "    + Decrypt and decode ...... Correct." << endl;
    decryptor.decrypt(rotated, plain);
    vector<double> result;
    ckks_encoder.decode(plain, result);
    print_vector(result, 3, 7);

    /*
    With the CKKS scheme it is also possible to evaluate a complex conjugation on
    a vector of encrypted complex numbers, using Evaluator::complex_conjugate.
    This is in fact a kind of rotation, and requires also Galois keys.
    */
}

void example_rotation()
{
    print_example_banner("Example: Rotation");

    /*
    Run all rotation examples.
    */
    example_rotation_bfv();
    // example_rotation_ckks();
}
