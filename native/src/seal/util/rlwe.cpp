// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ciphertext.h"
#include "seal/randomgen.h"
#include "seal/randomtostd.h"
#include "seal/util/clipnormal.h"
#include "seal/util/common.h"
#include "seal/util/globals.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/rlwe.h"
#include <iostream>
#include <iomanip>
#include <fstream>

using namespace std;

namespace seal
{
    namespace util
    {
        void sample_poly_ternary(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            RandomToStandardAdapter engine(prng);
            uniform_int_distribution<uint64_t> dist(0, 2);

            SEAL_ITERATE(iter(destination), coeff_count, [&](auto &I) {
                uint64_t rand = dist(engine);
                uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(rand == 0));
                SEAL_ITERATE(
                    iter(StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus), coeff_modulus_size,
                    [&](auto J) { *get<0>(J) = rand + (flag & get<1>(J).value()) - 1; });
            });
        }

        void sample_poly_normal(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            if (are_close(global_variables::noise_max_deviation, 0.0))
            {
                set_zero_poly(coeff_count, coeff_modulus_size, destination);
                return;
            }

            RandomToStandardAdapter engine(prng);
            ClippedNormalDistribution dist(
                0, global_variables::noise_standard_deviation, global_variables::noise_max_deviation);

            SEAL_ITERATE(iter(destination), coeff_count, [&](auto &I) {
                int64_t noise = static_cast<int64_t>(dist(engine));
                uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(noise < 0));
                SEAL_ITERATE(
                    iter(StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus), coeff_modulus_size,
                    [&](auto J) { *get<0>(J) = static_cast<uint64_t>(noise) + (flag & get<1>(J).value()); });
            });
        }

        void sample_poly_cbd(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            if (are_close(global_variables::noise_max_deviation, 0.0))
            {
                set_zero_poly(coeff_count, coeff_modulus_size, destination);
                return;
            }

            if (!are_close(global_variables::noise_standard_deviation, 3.2))
            {
                throw logic_error("centered binomial distribution only supports standard deviation 3.2; use rounded "
                                  "Gaussian instead");
            }

            auto cbd = [&]() {
                unsigned char x[6];
                prng->generate(6, reinterpret_cast<seal_byte *>(x));
                x[2] &= 0x1F;
                x[5] &= 0x1F;
                return hamming_weight(x[0]) + hamming_weight(x[1]) + hamming_weight(x[2]) - hamming_weight(x[3]) -
                       hamming_weight(x[4]) - hamming_weight(x[5]);
            };

            SEAL_ITERATE(iter(destination), coeff_count, [&](auto &I) {
                int32_t noise = cbd();
                uint64_t flag = static_cast<uint64_t>(-static_cast<int64_t>(noise < 0));
                SEAL_ITERATE(
                    iter(StrideIter<uint64_t *>(&I, coeff_count), coeff_modulus), coeff_modulus_size,
                    [&](auto J) { *get<0>(J) = static_cast<uint64_t>(noise) + (flag & get<1>(J).value()); });
            });
        }

        void sample_poly_uniform(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            // Extract encryption parameters
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t dest_byte_count = mul_safe(coeff_modulus_size, coeff_count, sizeof(uint64_t));

            constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);

            // Fill the destination buffer with fresh randomness
            prng->generate(dest_byte_count, reinterpret_cast<seal_byte *>(destination));

            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                auto &modulus = coeff_modulus[j];
                uint64_t max_multiple = max_random - barrett_reduce_64(max_random, modulus) - 1;
                transform(destination, destination + coeff_count, destination, [&](uint64_t rand) {
                    // This ensures uniform distribution
                    while (rand >= max_multiple)
                    {
                        prng->generate(sizeof(uint64_t), reinterpret_cast<seal_byte *>(&rand));
                    }
                    return barrett_reduce_64(rand, modulus);
                });
                destination += coeff_count;
            }
        }

        void sample_poly_uniform_seal_3_5(
            shared_ptr<UniformRandomGenerator> prng, const EncryptionParameters &parms, uint64_t *destination)
        {
            // Extract encryption parameters
            auto coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();

            RandomToStandardAdapter engine(prng);

            constexpr uint64_t max_random = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
            for (size_t j = 0; j < coeff_modulus_size; j++)
            {
                auto &modulus = coeff_modulus[j];
                uint64_t max_multiple = max_random - barrett_reduce_64(max_random, modulus) - 1;
                for (size_t i = 0; i < coeff_count; i++)
                {
                    // This ensures uniform distribution
                    uint64_t rand;
                    do
                    {
                        rand = (static_cast<uint64_t>(engine()) << 32) | static_cast<uint64_t>(engine());
                    } while (rand >= max_multiple);
                    destination[i + j * coeff_count] = barrett_reduce_64(rand, modulus);
                }
            }
        }

        void encrypt_zero_asymmetric(
            const PublicKey &public_key, const SEALContext &context, parms_id_type parms_id, bool is_ntt_form,
            Ciphertext &destination)
        {
#ifdef SEAL_DEBUG
            if (!is_valid_for(public_key, context))
            {
                throw invalid_argument("public key is not valid for the encryption parameters");
            }
#endif
            // We use a fresh memory pool with `clear_on_destruction' enabled
            MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

            auto &context_data = *context.get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = public_key.data().size();

            // Make destination have right size and parms_id
            // Ciphertext (c_0,c_1, ...)
            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            // c[j] = public_key[j] * u + e[j] where e[j] <-- chi, u <-- R_3

            // Create a PRNG; u and the noise/error share the same PRNG
            auto prng = parms.random_generator()->create();

            // Generate u <-- R_3
            auto u(allocate_poly(coeff_count, coeff_modulus_size, pool));
            sample_poly_ternary(prng, parms, u.get());

            // c[j] = u * public_key[j]
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                ntt_negacyclic_harvey(u.get() + i * coeff_count, ntt_tables[i]);
                for (size_t j = 0; j < encrypted_size; j++)
                {
                    dyadic_product_coeffmod(
                        u.get() + i * coeff_count, public_key.data().data(j) + i * coeff_count, coeff_count,
                        coeff_modulus[i], destination.data(j) + i * coeff_count);

                    // Addition with e_0, e_1 is in non-NTT form
                    if (!is_ntt_form)
                    {
                        inverse_ntt_negacyclic_harvey(destination.data(j) + i * coeff_count, ntt_tables[i]);
                    }
                }
            }

            // Generate e_j <-- chi
            // c[j] = public_key[j] * u + e[j]
            for (size_t j = 0; j < encrypted_size; j++)
            {
                SEAL_NOISE_SAMPLER(prng, parms, u.get());
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Addition with e_0, e_1 is in NTT form
                    if (is_ntt_form)
                    {
                        ntt_negacyclic_harvey(u.get() + i * coeff_count, ntt_tables[i]);
                    }
                    add_poly_coeffmod(
                        u.get() + i * coeff_count, destination.data(j) + i * coeff_count, coeff_count, coeff_modulus[i],
                        destination.data(j) + i * coeff_count);
                }
            }
        }

        void encrypt_zero_symmetric(
            const SecretKey &secret_key, const SEALContext &context, parms_id_type parms_id, bool is_ntt_form,
            bool save_seed, Ciphertext &destination)
        {
#ifdef SEAL_DEBUG
            if (!is_valid_for(secret_key, context))
            {
                throw invalid_argument("secret key is not valid for the encryption parameters");
            }
#endif
            // We use a fresh memory pool with `clear_on_destruction' enabled.
            MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

            auto &context_data = *context.get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = 2;

            // If a polynomial is too small to store UniformRandomGeneratorInfo,
            // it is best to just disable save_seed. Note that the size needed is
            // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
            // of an indicator word that indicates a seeded ciphertext.
            size_t poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
            size_t prng_info_byte_count =
                static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
            size_t prng_info_uint64_count =
                divide_round_up(prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
            if (save_seed && poly_uint64_count < prng_info_uint64_count + 1)
            {
                save_seed = false;
            }

            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            // Create an instance of a random number generator. We use this for sampling
            // a seed for a second PRNG used for sampling u (the seed can be public
            // information. This PRNG is also used for sampling the noise/error below.
            // prng_seed_type seed;
            // for (auto &i : seed)
            // {
            //     i = 1000ull;
            // }

            auto bootstrap_prng = parms.random_generator()->create();

            // Sample a public seed for generating uniform randomness
            prng_seed_type public_prng_seed;
            bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<seal_byte *>(public_prng_seed.data()));

            // Set up a new default PRNG for expanding u from the seed sampled above
            auto ciphertext_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);

            // Generate ciphertext: (c[0], c[1]) = ([-(as+e)]_q, a)
            uint64_t *c0 = destination.data();
            uint64_t *c1 = destination.data(1);

            // Sample a uniformly at random
            if (is_ntt_form || !save_seed)
            {
                // Sample the NTT form directly
                sample_poly_uniform(ciphertext_prng, parms, c1);
            }
            else if (save_seed)
            {
                // Sample non-NTT form and store the seed
                sample_poly_uniform(ciphertext_prng, parms, c1);
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into NTT representation
                    ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
            }

            // Sample e <-- chi
            auto noise(allocate_poly(coeff_count, coeff_modulus_size, pool));
            SEAL_NOISE_SAMPLER(bootstrap_prng, parms, noise.get());

            // Calculate -(a*s + e) (mod q) and store in c[0]
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count, c1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation
                    ntt_negacyclic_harvey(noise.get() + i * coeff_count, ntt_tables[i]);
                }
                else
                {
                    inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
                }
                add_poly_coeffmod(
                    noise.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                negate_poly_coeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
            }

            if (!is_ntt_form && !save_seed)
            {
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into non-NTT representation
                    inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
            }

            if (save_seed)
            {
                UniformRandomGeneratorInfo prng_info = ciphertext_prng->info();

                // Write prng_info to destination.data(1) after an indicator word
                c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
                prng_info.save(reinterpret_cast<seal_byte *>(c1 + 1), prng_info_byte_count, compr_mode_type::none);
            }
        }



        void encrypt_zero_symmetric_crp_round_two(const SecretKey &secret_key, const SEALContext &context, parms_id_type parms_id, bool is_ntt_form,
            bool save_seed, Ciphertext &destination, Ciphertext &ref, SecretKey &u_)
        {
            #ifdef SEAL_DEBUG
            if (!is_valid_for(secret_key, context))
            {
                throw invalid_argument("secret key is not valid for the encryption parameters");
            }
#endif
            // We use a fresh memory pool with `clear_on_destruction' enabled.
            MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

            auto &context_data = *context.get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = 2;

            // If a polynomial is too small to store UniformRandomGeneratorInfo,
            // it is best to just disable save_seed. Note that the size needed is
            // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
            // of an indicator word that indicates a seeded ciphertext.
            size_t poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
            size_t prng_info_byte_count =
                static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
            size_t prng_info_uint64_count =
                divide_round_up(prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
            if (save_seed && poly_uint64_count < prng_info_uint64_count + 1)
            {
                save_seed = false;
            }

            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;


            auto bootstrap_prng1 = parms.random_generator()->create();
            // Sample a public seed for generating uniform randomness

            prng_seed_type public_prng_seed1;
            bootstrap_prng1->generate(prng_seed_byte_count, reinterpret_cast<seal_byte *>(public_prng_seed1.data()));
            // Set up a new default PRNG for expanding u from the seed sampled above
            auto ciphertext_prng1 = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed1);

            // Generate ciphertext: (c[0], c[1]) = ([-(as+e)]_q, a)
            uint64_t *c0 = destination.data();
            uint64_t *c1 = destination.data(1);

            uint64_t *h0 = ref.data();
            uint64_t *h1 = ref.data(1);


            auto noise0(allocate_poly(coeff_count, coeff_modulus_size, pool));
            SEAL_NOISE_SAMPLER(bootstrap_prng1, parms, noise0.get());
            auto noise1(allocate_poly(coeff_count, coeff_modulus_size, pool));
            SEAL_NOISE_SAMPLER(bootstrap_prng1, parms, noise1.get());
            auto temp(allocate_poly(coeff_count, coeff_modulus_size, pool));
            //processing c0=s*h0+e2
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count, h0 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                    // sub_poly_coeffmod(u_.data().data()+ i * coeff_count, secret_key.data().data(), coeff_count, coeff_modulus[i],temp.get()+ i * coeff_count);
                    // dyadic_product_coeffmod(
                    // temp.get() + i * coeff_count, h1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    // c1+ i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation
                    ntt_negacyclic_harvey(noise0.get() + i * coeff_count, ntt_tables[i]);
                    // ntt_negacyclic_harvey(noise1.get() + i * coeff_count, ntt_tables[i]);
                }
                else
                {
                    inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
                    // inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
                add_poly_coeffmod(
                    noise0.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                // add_poly_coeffmod(
                //     noise1.get() + i * coeff_count, c1 + i * coeff_count, coeff_count, coeff_modulus[i],
                //     c1 + i * coeff_count);
                // negate_poly_coeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
                // negate_poly_coeffmod(c1 + i * coeff_count, coeff_count, coeff_modulus[i], c1 + i * coeff_count);
            }

            //processing c1=(u-s)h1+e3
             for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                // dyadic_product_coeffmod(
                //     secret_key.data().data() + i * coeff_count, h0 + i * coeff_count, coeff_count, coeff_modulus[i],
                //     c0 + i * coeff_count);

                    // cout<<"u  "<<*u_.data().data()<<endl;
                    // cout<< "sk  "<<*secret_key.data().data()<<endl;
                    // cout<<"coeff modulus  "<<coeff_modulus[i].value()<<endl;
                    // sub_poly_coeffmod(u_.data().data()+ i * coeff_count, secret_key.data().data()+ i * coeff_count, coeff_count, coeff_modulus[i],c1+ i * coeff_count);
                    // cout<<"temp  "<<*temp.get()<<endl;
                    // dyadic_product_coeffmod(
                    // c1 + i * coeff_count, h1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    // c1+ i * coeff_count);
                    dyadic_product_coeffmod(
                    u_.data().data() + i * coeff_count, h1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c1+ i * coeff_count);
                    
                    
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation
                    // ntt_negacyclic_harvey(noise0.get() + i * coeff_count, ntt_tables[i]);
                    ntt_negacyclic_harvey(noise1.get() + i * coeff_count, ntt_tables[i]);
                }
                else
                {
                    // inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
                    inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
                // add_poly_coeffmod(
                //     noise0.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
                //     c0 + i * coeff_count);
                add_poly_coeffmod(
                    noise1.get() + i * coeff_count, c1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c1 + i * coeff_count);
                // negate_poly_coeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
                // negate_poly_coeffmod(c1 + i * coeff_count, coeff_count, coeff_modulus[i], c1 + i * coeff_count);
            }





        }

        void encrypt_zero_symmetric_crp_round_one(const SecretKey &secret_key, const SEALContext &context, const SecretKey &u_poly,parms_id_type parms_id, bool is_ntt_form,
            bool save_seed, Ciphertext &destination)
        {
            #ifdef SEAL_DEBUG
            if (!is_valid_for(secret_key, context))
            {
                throw invalid_argument("secret key is not valid for the encryption parameters");
            }
#endif
            // We use a fresh memory pool with `clear_on_destruction' enabled.
            MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

            auto &context_data = *context.get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = 2;

            // If a polynomial is too small to store UniformRandomGeneratorInfo,
            // it is best to just disable save_seed. Note that the size needed is
            // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
            // of an indicator word that indicates a seeded ciphertext.
            size_t poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
            size_t prng_info_byte_count =
                static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
            size_t prng_info_uint64_count =
                divide_round_up(prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
            if (save_seed && poly_uint64_count < prng_info_uint64_count + 1)
            {
                save_seed = false;
            }

            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            prng_seed_type seed;
            for (auto &i : seed)
            {
                i = 1000ull;
            }

            auto bootstrap_prng = parms.random_generator()->create(seed);
            auto bootstrap_prng1 = parms.random_generator()->create();
            // Sample a public seed for generating uniform randomness
            prng_seed_type public_prng_seed;
            bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<seal_byte *>(public_prng_seed.data()));
            prng_seed_type public_prng_seed1;
            bootstrap_prng1->generate(prng_seed_byte_count, reinterpret_cast<seal_byte *>(public_prng_seed1.data()));
            // Set up a new default PRNG for expanding u from the seed sampled above
            auto ciphertext_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);
            auto ciphertext_prng1 = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed1);

            // Generate ciphertext: (c[0], c[1]) = ([-(as+e)]_q, a)
            uint64_t *c0 = destination.data();
            uint64_t *c1 = destination.data(1);

            //noise generating e0. e1
            auto noise0(allocate_poly(coeff_count, coeff_modulus_size, pool));
            SEAL_NOISE_SAMPLER(bootstrap_prng1, parms, noise0.get());
            auto noise1(allocate_poly(coeff_count, coeff_modulus_size, pool));
            SEAL_NOISE_SAMPLER(bootstrap_prng1, parms, noise1.get());


            //a generating
            auto a_crp(allocate_poly(coeff_count, coeff_modulus_size, pool));
            // Calculate -(a*s + e2) (mod q) and store in c[1]
            // Sample a uniformly at random
            if (is_ntt_form || !save_seed)
            {
                // Sample the NTT form directly
                sample_poly_uniform(ciphertext_prng, parms, a_crp.get());
            }
            else if (save_seed)
            {
                // Sample non-NTT form and store the seed
                sample_poly_uniform(ciphertext_prng, parms, a_crp.get());
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into NTT representation
                    ntt_negacyclic_harvey(a_crp.get() + i * coeff_count, ntt_tables[i]);
                }
            }

            // cout<< "a" <<endl;
            // cout<< *a_crp.get()<<endl;

            // Calculate a*s+e1 (mod q) and store in c[1]
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count, a_crp.get() + i * coeff_count, coeff_count, coeff_modulus[i],
                    c1 + i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation
                    ntt_negacyclic_harvey(noise1.get() + i * coeff_count, ntt_tables[i]);
                }
                else
                {
                    inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
                add_poly_coeffmod(
                    noise1.get() + i * coeff_count, c1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c1 + i * coeff_count);
                // negate_poly_coeffmod(c1 + i * coeff_count, coeff_count, coeff_modulus[i], c1 + i * coeff_count);
            }

            auto temp(allocate_poly(coeff_count, coeff_modulus_size, pool));

            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                dyadic_product_coeffmod(
                    u_poly.data().data() + i * coeff_count, a_crp.get() + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation
                    ntt_negacyclic_harvey(noise0.get() + i * coeff_count, ntt_tables[i]);
                }
                else
                {
                    inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
                }
                add_poly_coeffmod(
                    noise0.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                negate_poly_coeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
            }

        }

        void encrypt_zero_symmetric_crp(
            const SecretKey &secret_key, const SEALContext &context, parms_id_type parms_id, bool is_ntt_form,
            bool save_seed, Ciphertext &destination)
        {
#ifdef SEAL_DEBUG
            if (!is_valid_for(secret_key, context))
            {
                throw invalid_argument("secret key is not valid for the encryption parameters");
            }
#endif
            // We use a fresh memory pool with `clear_on_destruction' enabled.
            MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);

            auto &context_data = *context.get_context_data(parms_id);
            auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_modulus_size = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = 2;

            // If a polynomial is too small to store UniformRandomGeneratorInfo,
            // it is best to just disable save_seed. Note that the size needed is
            // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
            // of an indicator word that indicates a seeded ciphertext.
            size_t poly_uint64_count = mul_safe(coeff_count, coeff_modulus_size);
            size_t prng_info_byte_count =
                static_cast<size_t>(UniformRandomGeneratorInfo::SaveSize(compr_mode_type::none));
            size_t prng_info_uint64_count =
                divide_round_up(prng_info_byte_count, static_cast<size_t>(bytes_per_uint64));
            if (save_seed && poly_uint64_count < prng_info_uint64_count + 1)
            {
                save_seed = false;
            }

            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            // Create an instance of a random number generator. We use this for sampling
            // a seed for a second PRNG used for sampling u (the seed can be public
            // information. This PRNG is also used for sampling the noise/error below.
            prng_seed_type seed;
            for (auto &i : seed)
            {
                i = 1000ull;
            }

            auto bootstrap_prng = parms.random_generator()->create(seed);
            auto bootstrap_prng1 = parms.random_generator()->create();
            // Sample a public seed for generating uniform randomness
            prng_seed_type public_prng_seed;
            bootstrap_prng->generate(prng_seed_byte_count, reinterpret_cast<seal_byte *>(public_prng_seed.data()));

            // Set up a new default PRNG for expanding u from the seed sampled above
            auto ciphertext_prng = UniformRandomGeneratorFactory::DefaultFactory()->create(public_prng_seed);

            // Generate ciphertext: (c[0], c[1]) = ([-(as+e)]_q, a)
            uint64_t *c0 = destination.data();
            uint64_t *c1 = destination.data(1);

            // Sample a uniformly at random
            if (is_ntt_form || !save_seed)
            {
                // Sample the NTT form directly
                sample_poly_uniform(ciphertext_prng, parms, c1);
            }
            else if (save_seed)
            {
                // Sample non-NTT form and store the seed
                sample_poly_uniform(ciphertext_prng, parms, c1);
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into NTT representation
                    ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
            }

            // Sample e <-- chi
            auto noise(allocate_poly(coeff_count, coeff_modulus_size, pool));
            SEAL_NOISE_SAMPLER(bootstrap_prng, parms, noise.get());

            // Calculate -(a*s + e) (mod q) and store in c[0]
            for (size_t i = 0; i < coeff_modulus_size; i++)
            {
                // cout<< "sk   :" << *secret_key.data().data() <<endl;
                // cout<< "pk c1  :" << *c1<<endl;
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count, c1 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                // cout<< "pk c0 (product)  :" << *c0<<endl;
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation
                    ntt_negacyclic_harvey(noise.get() + i * coeff_count, ntt_tables[i]);
                }
                else
                {
                    inverse_ntt_negacyclic_harvey(c0 + i * coeff_count, ntt_tables[i]);
                }
                add_poly_coeffmod(
                    noise.get() + i * coeff_count, c0 + i * coeff_count, coeff_count, coeff_modulus[i],
                    c0 + i * coeff_count);
                negate_poly_coeffmod(c0 + i * coeff_count, coeff_count, coeff_modulus[i], c0 + i * coeff_count);
            }

            if (!is_ntt_form && !save_seed)
            {
                for (size_t i = 0; i < coeff_modulus_size; i++)
                {
                    // Transform the c1 into non-NTT representation
                    inverse_ntt_negacyclic_harvey(c1 + i * coeff_count, ntt_tables[i]);
                }
            }

            if (save_seed)
            {
                UniformRandomGeneratorInfo prng_info = ciphertext_prng->info();

                // Write prng_info to destination.data(1) after an indicator word
                c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
                prng_info.save(reinterpret_cast<seal_byte *>(c1 + 1), prng_info_byte_count, compr_mode_type::none);
            }
        }


        
    } // namespace util
} // namespace seal
