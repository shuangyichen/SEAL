// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_levels()
{
    print_example_banner("Example: Inner product of two vectors");

    /*
    [BatchEncoder] (For BFV scheme only)

    Let N denote the poly_modulus_degree and T denote the plain_modulus. Batching
    allows the BFV plaintext polynomials to be viewed as 2-by-(N/2) matrices, with
    each element an integer modulo T. In the matrix view, encrypted operations act
    element-wise on encrypted matrices, allowing the user to obtain speeds-ups of
    several orders of magnitude in fully vectorizable computations. Thus, in all
    but the simplest computations, batching should be the preferred method to use
    with BFV, and when used properly will result in implementations outperforming
    anything done without batching.
    */
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    /*
    To enable batching, we need to set the plain_modulus to be a prime number
    congruent to 1 modulo 2*poly_modulus_degree. Microsoft SEAL provides a helper
    method for finding such a prime. In this example we create a 20-bit prime
    that supports batching.
    */
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    /*
    We can verify that batching is indeed enabled by looking at the encryption
    parameter qualifiers created by SEALContext.
    */
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;


    vector<SecretKey> SKS(3);
    vector<PublicKey> PKS(3);
    vector<RelinKeys> RKS_round_one(3);
    vector<GaloisKeys> galois_keys_set(3);


    KeyGenerator keygen1(context);
    KeyGenerator keygen2(context);
    KeyGenerator keygen3(context);
    vector<int> steps(2);
    steps[0] = 1;
    steps[1] = 5;
    //party0
    print_line(__LINE__);
    cout <<"Party 0 generating key pair"<< endl;
    SKS[0] = keygen1.secret_key();
    keygen1.create_public_key_crp(PKS[0]);
    keygen1.create_relin_keys_round_one(RKS_round_one[0]);
    keygen1.create_galois_keys_crp(steps,galois_keys_set[0]);
    //party1
    print_line(__LINE__);
    cout <<"Party 1 generating key pair"<< endl;
    SKS[1] = keygen2.secret_key();
    keygen2.create_public_key_crp(PKS[1]);
    keygen2.create_relin_keys_round_one(RKS_round_one[1]);
    keygen2.create_galois_keys_crp(steps,galois_keys_set[1]);
    //party2
    print_line(__LINE__);
    cout <<"Party 2 generating key pair"<< endl;
    SKS[2] = keygen3.secret_key();
    keygen3.create_public_key_crp(PKS[2]);
    keygen3.create_relin_keys_round_one(RKS_round_one[2]);
    keygen3.create_galois_keys_crp(steps,galois_keys_set[2]);
    PublicKey CPK;
    SecretKey CSK;
    RelinKeys Relin_key_round_one;
    RelinKeys Relin_key_round_two;
    KeyGenerator keygen(context);
    // // KeyGenerator keygen(context);
    print_line(__LINE__);
    cout <<"Server aggregating public keys to generate common public key"<< endl;
    keygen.create_common_public_key(CPK,PKS,3);
    keygen.create_common_secret_key(CSK,SKS,3);
    print_line(__LINE__);
    cout <<"Server aggregating rotation keys to generate common rotation key"<< endl;
    GaloisKeys cRotKeys;
    keygen.gen_common_galois_keys(galois_keys_set,steps, 3,cRotKeys);
   
    print_line(__LINE__);
    cout <<"Server aggregating relinearization key share of round 1 to generate common relin key share of round 1"<< endl;
    keygen.aggregate_relin_keys_round_one(Relin_key_round_one,RKS_round_one,3);
    // cout <<"Generate relin key round one"<< endl;
    // cout<< "Relin_key_round_one"<<endl;
    // cout<< Relin_key_round_one.data().size()<<endl;
    // cout<< Relin_key_round_one.data()[0].size()<<endl;
    // cout<< Relin_key_round_one.data()[0][0].size()<<endl;
    // //relin key round 2
    vector<RelinKeys> RKS_round_two(3);

    print_line(__LINE__);
    cout <<"Party 0 generating relin keys share of round 2 based on common relin key share of round 1"<< endl;
    keygen1.create_relin_keys_round_two(RKS_round_two[0],Relin_key_round_one);
    print_line(__LINE__);
    cout <<"Party 1 generating relin keys share of round 2 based on common relin key share of round 1"<< endl;
    keygen2.create_relin_keys_round_two(RKS_round_two[1],Relin_key_round_one);
    print_line(__LINE__);
    cout <<"Party 2 generating relin keys share of round 2 based on common relin key share of round 1"<< endl;
    keygen3.create_relin_keys_round_two(RKS_round_two[2],Relin_key_round_one);
    // cout <<"Round two share generating"<< endl;
    print_line(__LINE__);
    cout <<"Server aggregating relinearization key share of round 2 to generate common relin key "<< endl;
    keygen.aggregate_relin_keys_round_two(Relin_key_round_two,Relin_key_round_one,RKS_round_two,3);
    // cout <<"RelinKey generated"<< endl;
    Encryptor encryptor(context, CPK);
    Evaluator evaluator(context);
    Decryptor decryptor(context, CSK);



    /*
    Batching is done through an instance of the BatchEncoder class.
    */
    BatchEncoder batch_encoder(context);
    
    /*
    The total number of batching `slots' equals the poly_modulus_degree, N, and
    these slots are organized into 2-by-(N/2) matrices that can be encrypted and
    computed on. Each slot contains an integer modulo plain_modulus.
    */
    size_t slot_count = batch_encoder.slot_count();
    // size_t row_size = slot_count / 2;
    // cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    The matrix plaintext is simply given to BatchEncoder as a flattened vector
    of numbers. The first `row_size' many numbers form the first row, and the
    rest form the second row. Here we create the following matrix:

        [ 0,  1,  2,  3,  0,  0, ...,  0 ]
        [ 4,  5,  6,  7,  0,  0, ...,  0 ]
    */
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 1ULL;
    pod_matrix[1] = 2ULL;
    pod_matrix[2] = 3ULL;
    pod_matrix[3] = 4ULL;
    pod_matrix[4] = 5ULL;
    // pod_matrix[row_size] = 4ULL;
    // pod_matrix[row_size + 1] = 5ULL;
    // pod_matrix[row_size + 2] = 6ULL;
    // pod_matrix[row_size + 3] = 7ULL;

    cout << "Input plaintext vector:" << endl;
    print_vector(pod_matrix, 6);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode plaintext vector:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    We can instantly decode to verify correctness of the encoding. Note that no
    encryption or decryption has yet taken place.
    */
    // vector<uint64_t> pod_result;
    // cout << "    + Decode plaintext matrix ...... Correct." << endl;
    // batch_encoder.decode(plain_matrix, pod_result);
    // print_vector(pod_result, 5);

    /*
    Next we encrypt the encoded plaintext.
    */
    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "Encrypt plain_vector to encrypted_vector." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    // cout << "    + Noise budget in encrypted_matrix: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
    //      << endl;

    /*
    Operating on the ciphertext results in homomorphic operations being performed
    simultaneously in all 8192 slots (matrix elements). To illustrate this, we
    form another plaintext matrix

        [ 1,  2,  1,  2,  1,  2, ..., 2 ]
        [ 1,  2,  1,  2,  1,  2, ..., 2 ]

    and encode it into a plaintext.
    */
    vector<uint64_t> pod_matrix2(slot_count, 0ULL);
    pod_matrix2[0] = 1ULL;
    pod_matrix2[1] = 2ULL;
    pod_matrix2[2] = 1ULL;
    pod_matrix2[3] = 2ULL;
    pod_matrix2[4] = 1ULL;
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext vector:" << endl;
    print_vector(pod_matrix2, 6);

    /*
    We now add the second (plaintext) matrix to the encrypted matrix, and square
    the sum.
    */
    // print_line(__LINE__);
    // Plaintext plain_result2;
 
    Ciphertext encrypted_matrix2;
    print_line(__LINE__);
    cout << "Encrypt plain_vector2 to encrypted_vector2." << endl;
    encryptor.encrypt(plain_matrix2, encrypted_matrix2);
    // vector<uint64_t> pod_result4;
    // cout << "Sum, square, and relinearize." << endl;
    // encrypted_matrix2
    print_line(__LINE__);
    cout << "Multiply encrypted_vector with encrypted_vector2." << endl;
    evaluator.multiply_inplace(encrypted_matrix,encrypted_matrix2);

    cout << "Scalar multiplication result." << endl;
    Plaintext result_inter;
    decryptor.decrypt(encrypted_matrix,result_inter);
    vector<uint64_t> pod_result;
    batch_encoder.decode(result_inter,pod_result);
    cout << endl;
    cout << "Element-wise multiplication result :" << endl;
    print_vector(pod_result, 6);


    cout << "Relinearization after multiplication." << endl;
    evaluator.relinearize_inplace(encrypted_matrix, Relin_key_round_two);

    Ciphertext ct_dup;
    // cout << "Copy." << endl;
    evaluator.rotate_rows(encrypted_matrix,5,cRotKeys,ct_dup);
    evaluator.add_inplace(ct_dup,encrypted_matrix);
  
    Ciphertext rot_res;
    evaluator.rotate_rows(encrypted_matrix,1,cRotKeys,rot_res);
    Plaintext result_rot_;
    decryptor.decrypt(rot_res,result_rot_);
    batch_encoder.decode(result_rot_,pod_result);
    cout << endl;
    cout << "Rotate 1 steps to the left" << endl;
    print_vector(pod_result, 6);
    evaluator.add_inplace(ct_dup,rot_res);
    for (int i=2;i<5;i++){
        // Ciphertext tmp;
        evaluator.rotate_rows(rot_res,1,cRotKeys,rot_res);
        evaluator.add_inplace(ct_dup,rot_res);
    }


    cout << endl;
    cout << "Rotate 2 steps to the left" << endl;
    cout << endl;
    cout << "    [ 3, 8, 5, 0, 0, 0, ..., 0, 0, 0, 0, 0, 0 ]" << endl;
    cout << endl;
    cout << "Rotate 3 steps to the left" << endl;
    cout << endl;
    cout << "    [ 8, 5, 0, 0, 0, 0, ..., 0, 0, 0, 0, 0, 0 ]" << endl;
    cout << endl;
    cout << "Rotate 4 steps to the left" << endl;
    cout << endl;
    cout << "    [ 5, 0, 0, 0, 0, 0, ..., 0, 0, 0, 0, 0, 0 ]" << endl;


     Plaintext add;
    decryptor.decrypt(ct_dup,add);
    batch_encoder.decode(add,pod_result);
    cout << endl;
    cout << "Rotation addition result" << endl;
    print_vector(pod_result, 6);


    vector<uint64_t> pod_matrix3(slot_count, 0ULL);
    pod_matrix3[0] = 1ULL;
    Plaintext plain_matrix3;
    batch_encoder.encode(pod_matrix3, plain_matrix3);
    cout << endl;
    cout << "Masking vector:" << endl;
    print_vector(pod_matrix3, 6);
    cout << "Encoding masking vector ..." << endl;
    cout << endl;
    cout << "Multiply the addition result with the masking vector ..." << endl;
    evaluator.multiply_plain_inplace(ct_dup,plain_matrix3);
    Plaintext result_pt;
    decryptor.decrypt(ct_dup,result_pt);
    // vector<uint64_t> pod_result;
    batch_encoder.decode(result_pt,pod_result);
    cout << endl;
    cout << "Inner product result :" << endl;
    print_vector(pod_result, 1);

    
    

    // evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    // Plaintext plain_result4;
    // decryptor.decrypt(ct_dup, plain_result4);
    // vector<uint64_t> pod_result4;
    // batch_encoder.decode(plain_result4, pod_result4);
    // // cout << "    + Result plaintext matrix ...... Correct." << endl;
    // print_vector(pod_result4, 6);
    // print_line(__LINE__);
    // cout << "Element-wise square" << endl;
    // evaluator.square_inplace(encrypted_matrix);
    // print_line(__LINE__);
    // cout << "Using relin key after square" << endl;
    // evaluator.relinearize_inplace(encrypted_matrix, Relin_key_round_two);

    // /*
    // How much noise budget do we have left?
    // */
    // cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    // /*
    // We decrypt and decompose the plaintext to recover the result as a matrix.
    // */
    // Plaintext plain_result;
    // print_line(__LINE__);
    // cout << "Decrypt and decode result." << endl;
    // decryptor.decrypt(encrypted_matrix, plain_result);
    // batch_encoder.decode(plain_result, pod_result);
    // cout << "    + Result " << endl;
    // print_matrix(pod_result, row_size);

    /*
    Batching allows us to efficiently use the full plaintext polynomial when the
    desired encrypted computation is highly parallelizable. However, it has not
    solved the other problem mentioned in the beginning of this file: each slot
    holds only an integer modulo plain_modulus, and unless plain_modulus is very
    large, we can quickly encounter data type overflow and get unexpected results
    when integer computations are desired. Note that overflow cannot be detected
    in encrypted form. The CKKS scheme (and the CKKSEncoder) addresses the data
    type overflow issue, but at the cost of yielding only approximate results.
    */
}
