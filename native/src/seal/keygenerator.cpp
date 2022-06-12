// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/keygenerator.h"
#include "seal/randomtostd.h"
#include "seal/util/common.h"
#include "seal/util/galois.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/rlwe.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <algorithm>

using namespace std;
using namespace seal::util;

namespace seal
{
    KeyGenerator::KeyGenerator(const SEALContext &context) : context_(context)
    {
        // Verify parameters
        if (!context_.parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        // Secret key has not been generated
        sk_generated_ = false;

        // Generate the secret and public key
        generate_sk();
    }

    KeyGenerator::KeyGenerator(const SEALContext &context, const SecretKey &secret_key) : context_(context)
    {
        // Verify parameters
        if (!context_.parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
        if (!is_valid_for(secret_key, context_))
        {
            throw invalid_argument("secret key is not valid for encryption parameters");
        }

        // Set the secret key
        secret_key_ = secret_key;
        sk_generated_ = true;

        // Generate the public key
        generate_sk(sk_generated_);
    }

    void KeyGenerator::generate_sk(bool is_initialized)
    {
        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        if (!is_initialized)
        {
            // Initialize secret key.
            secret_key_ = SecretKey();
            sk_generated_ = false;
            secret_key_.data().resize(mul_safe(coeff_count, coeff_modulus_size));

            // Generate secret key
            RNSIter secret_key(secret_key_.data().data(), coeff_count);
            // cout << *secret_key_.data().data() << endl;
            sample_poly_ternary(parms.random_generator()->create(), parms, secret_key);
            // cout << *secret_key_.data().data() << endl;
            // Transform the secret s into NTT representation.
            auto ntt_tables = context_data.small_ntt_tables();
            ntt_negacyclic_harvey(secret_key, coeff_modulus_size, ntt_tables);

            // Set the parms_id for secret key
            secret_key_.parms_id() = context_data.parms_id();
        }

        // Set the secret_key_array to have size 1 (first power of secret)
        secret_key_array_ = allocate_poly(coeff_count, coeff_modulus_size, pool_);
        set_poly(secret_key_.data().data(), coeff_count, coeff_modulus_size, secret_key_array_.get());
        secret_key_array_size_ = 1;

        // Secret key has been generated
        sk_generated_ = true;
    }


    SecretKey KeyGenerator::generate_secret_key()
    {
        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

 
            // Initialize secret key.
            SecretKey sk;
            sk_generated_ = false;
            sk.data().resize(mul_safe(coeff_count, coeff_modulus_size));

            // Generate secret key
            RNSIter secret_key(sk.data().data(), coeff_count);

            sample_poly_ternary(parms.random_generator()->create(), parms, secret_key);
            // Transform the secret s into NTT representation.
            auto ntt_tables = context_data.small_ntt_tables();
            ntt_negacyclic_harvey(secret_key, coeff_modulus_size, ntt_tables);

            // Set the parms_id for secret key
            sk.parms_id() = context_data.parms_id();


        // Set the secret_key_array to have size 1 (first power of secret)
        util::Pointer<std::uint64_t> secret_key_array = allocate_poly(coeff_count, coeff_modulus_size, pool_);
        set_poly(sk.data().data(), coeff_count, coeff_modulus_size, secret_key_array.get());
        secret_key_array_size_ = 1;

        // Secret key has been generated
        sk_generated_ = true;
        return sk;
    }

    PublicKey KeyGenerator::generate_pk_with_sk(bool save_seed,SecretKey &sk) const
    {

        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        PublicKey public_key;
        encrypt_zero_symmetric(sk, context_, context_data.parms_id(), true, save_seed, public_key.data());

        // Set the parms_id for public key
        public_key.parms_id() = context_data.parms_id();

        return public_key;
    }

    PublicKey KeyGenerator::generate_pk(bool save_seed) const
    {
       
        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        PublicKey public_key;
        encrypt_zero_symmetric(secret_key_, context_, context_data.parms_id(), true, save_seed, public_key.data());

        // Set the parms_id for public key
        public_key.parms_id() = context_data.parms_id();

        return public_key;
    }

        PublicKey KeyGenerator::generate_pk_with_same_c1(bool save_seed, PublicKey &ref, SecretKey &sk) 
    {

        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        PublicKey public_key;
        encrypt_zero_symmetric_with_c1(sk, context_, context_data.parms_id(), true, save_seed, ref.data(),public_key.data());

        // Set the parms_id for public key
        public_key.parms_id() = context_data.parms_id();

        return public_key;
    }

    SecretKey KeyGenerator::generate_csk(vector<SecretKey> &sks, int party_num)
    {
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        //SecretKey CSK;
        SecretKey CSK;
        CSK.data().resize(mul_safe(coeff_count, coeff_modulus_size));

        for (size_t j = 0; j < coeff_modulus_size; j++){
            for (int i=0;i<party_num;++i){
            // add_poly_coeffmod(public_key_combined_.get(),pks[i].data().data(),coeff_count,coeff_modulus[j],public_key_combined_.get());
            add_poly_coeffmod(CSK.data().data()+ j * coeff_count,sks[i].data().data()+ j * coeff_count,coeff_count,coeff_modulus[j],CSK.data().data()+ j * coeff_count);
        }
        }

        // Set the parms_id for secret key
        CSK.parms_id() = context_data.parms_id();


        secret_key_array_ = allocate_poly(coeff_count, coeff_modulus_size, pool_);
        set_poly(CSK.data().data(), coeff_count, coeff_modulus_size, secret_key_array_.get());
        secret_key_array_size_ = 1;

        // Secret key has been generated
        sk_generated_ = true;
    return CSK;
        
    }
    PublicKey KeyGenerator::generate_cpk(vector<PublicKey> &pks, int party_num)
    {
        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_size = 2;
        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        PublicKey public_key;
        public_key.data().resize(context_, context_data.parms_id(), encrypted_size);
        public_key.data().is_ntt_form() = true;
        public_key.data().scale() = 1.0;
        public_key.data().correction_factor() = 1;
       
        for (size_t j = 0; j < coeff_modulus_size; j++){
            add_poly_coeffmod(
                    public_key.data().data(1)+ j * coeff_count,pks[0].data().data(1) + j * coeff_count , coeff_count, coeff_modulus[j],
                    public_key.data().data(1)+ j * coeff_count);
            for (int i=0;i<party_num;++i){
                add_poly_coeffmod(public_key.data().data()+j*coeff_count,pks[i].data().data()+j*coeff_count,coeff_count,coeff_modulus[j],public_key.data().data()+j*coeff_count);
        }
        }
        cout<<public_key.data().size()<<endl;
        return public_key;
    }

    RelinKeys KeyGenerator::create_relin_keys(size_t count, bool save_seed)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate relinearization keys for unspecified secret key");
        }
        if (!count || count > SEAL_CIPHERTEXT_SIZE_MAX - 2)
        {
            throw invalid_argument("invalid count");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Make sure we have enough secret keys computed
        compute_secret_key_array(context_data, count + 1);

        // Create the RelinKeys object to return
        RelinKeys relin_keys;

        // Assume the secret key is already transformed into NTT form.
        ConstPolyIter secret_key(secret_key_array_.get(), coeff_count, coeff_modulus_size);
        generate_kswitch_keys(secret_key + 1, count, static_cast<KSwitchKeys &>(relin_keys), save_seed);

        // Set the parms_id
        relin_keys.parms_id() = context_data.parms_id();

        return relin_keys;
    }

    GaloisKeys KeyGenerator::gen_common_galois_keys(const vector<uint32_t> &galois_elts,  vector<GaloisKeys> &rotKeys, int party_num)
    {
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto galois_tool = context_data.galois_tool();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t decomp_mod_count = context_.first_context_data()->parms().coeff_modulus().size();
        size_t rotKeys_size = rotKeys[0].data().size();



        GaloisKeys common_RotKeys;
        common_RotKeys.data().resize(coeff_count);
        for (auto galois_elt : galois_elts)
        {
            size_t index = GaloisKeys::get_index(galois_elt);
            // common_RotKeys.data()[index].resize(decomp_mod_count);


            for (size_t j = 0; j <party_num; ++j) {
                aggregate_rot_keys(rotKeys[j].data()[index],common_RotKeys.data()[index]);
            }
            // // SEAL_ITERATE(iter(),1, [&](auto I){
            // SEAL_ITERATE(iter(rotKeys[j].data()[index],coeff_modulus,common_RotKeys.data()[index], size_t(0)), decomp_mod_count, [&](auto I) {
            // CoeffIter singleRotKeyIter = (*iter(get<0>(I).data()))[get<3>(I)];
            // CoeffIter destination_iter = (*iter(get<2>(I).data()))[get<3>(I)];
            // add_poly_coeffmod(destination_iter, singleRotKeyIter, coeff_count, get<1>(I), destination_iter);
            // });
            // // });
            // }
        }
        common_RotKeys.parms_id_ = context_data.parms_id();
        // vector<uint32_t> galois_elts = galois_tool()->get_elts_all();
        // for (size_t j = 0; j < coeff_count; j++){
        //     for (int i=0;i<party_num;++i){
        //         add_poly_coeffmod(common_RotKeys.data(j).data(),rotKeys[i].data(j).data(),coeff_count,coeff_modulus[j],common_RotKeys.data(j).data());
        // }
        // }


        return common_RotKeys;
    }


    void KeyGenerator::aggregate_rot_keys(vector<PublicKey> &rotkey,vector<PublicKey> &destination)
    {
        size_t coeff_count = context_.key_context_data()->parms().poly_modulus_degree();
        size_t decomp_mod_count = context_.first_context_data()->parms().coeff_modulus().size();
        auto &key_context_data = *context_.key_context_data();
        auto &key_parms = key_context_data.parms();
        auto &key_modulus = key_parms.coeff_modulus();

        // Size check
        if (!product_fits_in(coeff_count, decomp_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
        destination.resize(decomp_mod_count);
            // SEAL_ITERATE(iter(),1, [&](auto I){
            SEAL_ITERATE(iter(rotkey,key_modulus,destination, size_t(0)), decomp_mod_count, [&](auto I) {
            CoeffIter singleRotKeyIter = (*iter(get<0>(I).data()))[get<3>(I)];
            CoeffIter destination_iter = (*iter(get<2>(I).data()))[get<3>(I)];
            add_poly_coeffmod(destination_iter, singleRotKeyIter, coeff_count, get<1>(I), destination_iter);
            });
            // });
            
    }
    GaloisKeys KeyGenerator::create_galois_keys_with_sk(const vector<uint32_t> &galois_elts, bool save_seed, SecretKey &sk)
    {
        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto galois_tool = context_data.galois_tool();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size, size_t(2)))
        {
            throw logic_error("invalid parameters");
        }
        // cout<<coeff_count<<endl;
        // cout<<coeff_modulus_size<<endl;

        // Create the GaloisKeys object to return
        GaloisKeys galois_keys;

        // The max number of keys is equal to number of coefficients
        galois_keys.data().resize(coeff_count);

        for (auto galois_elt : galois_elts)
        {
            // Verify coprime conditions.
            if (!(galois_elt & 1) || (galois_elt >= coeff_count << 1))
            {
                throw invalid_argument("Galois element is not valid");
            }

            // Do we already have the key?
            if (galois_keys.has_key(galois_elt))
            {
                continue;
            }

            // Rotate secret key for each coeff_modulus
            SEAL_ALLOCATE_GET_RNS_ITER(rotated_secret_key, coeff_count, coeff_modulus_size, pool_);
            RNSIter secret_key(sk.data().data(), coeff_count);
            galois_tool->apply_galois_ntt(secret_key, coeff_modulus_size, galois_elt, rotated_secret_key);

            // Initialize Galois key
            // This is the location in the galois_keys vector
            size_t index = GaloisKeys::get_index(galois_elt);

            // Create Galois keys.
            generate_one_kswitch_key(rotated_secret_key, galois_keys.data()[index], save_seed);
        }

        // Set the parms_id
        galois_keys.parms_id_ = context_data.parms_id();
        // cout<<galois_keys.data().data()<<endl;
        return galois_keys;
    }

    GaloisKeys KeyGenerator::create_galois_keys(const vector<uint32_t> &galois_elts, bool save_seed)
    {
        // Check to see if secret key and public key have been generated
        if (!sk_generated_)
        {
            throw logic_error("cannot generate Galois keys for unspecified secret key");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto galois_tool = context_data.galois_tool();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size, size_t(2)))
        {
            throw logic_error("invalid parameters");
        }

        // Create the GaloisKeys object to return
        GaloisKeys galois_keys;

        // The max number of keys is equal to number of coefficients
        galois_keys.data().resize(coeff_count);

        for (auto galois_elt : galois_elts)
        {
            // Verify coprime conditions.
            if (!(galois_elt & 1) || (galois_elt >= coeff_count << 1))
            {
                throw invalid_argument("Galois element is not valid");
            }

            // Do we already have the key?
            if (galois_keys.has_key(galois_elt))
            {
                continue;
            }

            // Rotate secret key for each coeff_modulus
            SEAL_ALLOCATE_GET_RNS_ITER(rotated_secret_key, coeff_count, coeff_modulus_size, pool_);
            RNSIter secret_key(secret_key_.data().data(), coeff_count);
            galois_tool->apply_galois_ntt(secret_key, coeff_modulus_size, galois_elt, rotated_secret_key);

            // Initialize Galois key
            // This is the location in the galois_keys vector
            size_t index = GaloisKeys::get_index(galois_elt);

            // Create Galois keys.
            generate_one_kswitch_key(rotated_secret_key, galois_keys.data()[index], save_seed);
        }

        // Set the parms_id
        galois_keys.parms_id_ = context_data.parms_id();
        // cout<<"galois keys size"<<endl;
        // cout<<galois_keys.data().size()<<endl;
        return galois_keys;
    }

    const SecretKey &KeyGenerator::secret_key() const
    {
        if (!sk_generated_)
        {
            throw logic_error("secret key has not been generated");
        }
        return secret_key_;
    }

    void KeyGenerator::compute_secret_key_array(const SEALContext::ContextData &context_data, size_t max_power)
    {
#ifdef SEAL_DEBUG
        if (max_power < 1)
        {
            throw invalid_argument("max_power must be at least 1");
        }
        if (!secret_key_array_size_ || !secret_key_array_)
        {
            throw logic_error("secret_key_array_ is uninitialized");
        }
#endif
        // Extract encryption parameters.
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size, max_power))
        {
            throw logic_error("invalid parameters");
        }

        ReaderLock reader_lock(secret_key_array_locker_.acquire_read());

        size_t old_size = secret_key_array_size_;
        size_t new_size = max(max_power, old_size);

        if (old_size == new_size)
        {
            return;
        }

        reader_lock.unlock();

        // Need to extend the array
        // Compute powers of secret key until max_power
        auto secret_key_array(allocate_poly_array(new_size, coeff_count, coeff_modulus_size, pool_));
        set_poly_array(secret_key_array_.get(), old_size, coeff_count, coeff_modulus_size, secret_key_array.get());
        RNSIter secret_key(secret_key_array.get(), coeff_count);

        PolyIter secret_key_power(secret_key_array.get(), coeff_count, coeff_modulus_size);
        secret_key_power += (old_size - 1);
        auto next_secret_key_power = secret_key_power + 1;

        // Since all of the key powers in secret_key_array_ are already NTT transformed, to get the next one we simply
        // need to compute a dyadic product of the last one with the first one [which is equal to NTT(secret_key_)].
        SEAL_ITERATE(iter(secret_key_power, next_secret_key_power), new_size - old_size, [&](auto I) {
            dyadic_product_coeffmod(get<0>(I), secret_key, coeff_modulus_size, coeff_modulus, get<1>(I));
        });

        // Take writer lock to update array
        WriterLock writer_lock(secret_key_array_locker_.acquire_write());

        // Do we still need to update size?
        old_size = secret_key_array_size_;
        new_size = max(max_power, secret_key_array_size_);

        if (old_size == new_size)
        {
            return;
        }

        // Acquire new array
        secret_key_array_size_ = new_size;
        secret_key_array_.acquire(secret_key_array);
    }

    void KeyGenerator::generate_one_kswitch_key(ConstRNSIter new_key, vector<PublicKey> &destination, bool save_seed)
    {
        if (!context_.using_keyswitching())
        {
            throw logic_error("keyswitching is not supported by the context");
        }

        size_t coeff_count = context_.key_context_data()->parms().poly_modulus_degree();
        size_t decomp_mod_count = context_.first_context_data()->parms().coeff_modulus().size();
        auto &key_context_data = *context_.key_context_data();
        auto &key_parms = key_context_data.parms();
        auto &key_modulus = key_parms.coeff_modulus();

        // Size check
        if (!product_fits_in(coeff_count, decomp_mod_count))
        {
            throw logic_error("invalid parameters");
        }

        // KSwitchKeys data allocated from pool given by MemoryManager::GetPool.
        destination.resize(decomp_mod_count);

        SEAL_ITERATE(iter(new_key, key_modulus, destination, size_t(0)), decomp_mod_count, [&](auto I) {
            SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_count, pool_);
            encrypt_zero_symmetric(
                secret_key_, context_, key_context_data.parms_id(), true, save_seed, get<2>(I).data());
            uint64_t factor = barrett_reduce_64(key_modulus.back().value(), get<1>(I));
            multiply_poly_scalar_coeffmod(get<0>(I), coeff_count, factor, get<1>(I), temp);

            // We use the SeqIter at get<3>(I) to find the i-th RNS factor of the first destination polynomial.
            CoeffIter destination_iter = (*iter(get<2>(I).data()))[get<3>(I)];
            add_poly_coeffmod(destination_iter, temp, coeff_count, get<1>(I), destination_iter);
        });
    }

    void KeyGenerator::generate_kswitch_keys(
        ConstPolyIter new_keys, size_t num_keys, KSwitchKeys &destination, bool save_seed)
    {
        size_t coeff_count = context_.key_context_data()->parms().poly_modulus_degree();
        auto &key_context_data = *context_.key_context_data();
        auto &key_parms = key_context_data.parms();
        size_t coeff_modulus_size = key_parms.coeff_modulus().size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size, num_keys))
        {
            throw logic_error("invalid parameters");
        }
#ifdef SEAL_DEBUG
        if (new_keys.poly_modulus_degree() != coeff_count)
        {
            throw invalid_argument("iterator is incompatible with encryption parameters");
        }
        if (new_keys.coeff_modulus_size() != coeff_modulus_size)
        {
            throw invalid_argument("iterator is incompatible with encryption parameters");
        }
#endif
        destination.data().resize(num_keys);
        SEAL_ITERATE(iter(new_keys, destination.data()), num_keys, [&](auto I) {
            this->generate_one_kswitch_key(get<0>(I), get<1>(I), save_seed);
        });
    }
} // namespace seal
