/**
 * @file standar_mucke.cpp
 * @brief File containing the implementation of the standard_Muckle protocol,
 *
 * @author Fernando Elena Benavente , felena@oesia.com
 *
 * @details the protocol is described in detail in the publication paper: https://eprint.iacr.org/2020/099.pdf
 *
 */

/****************************************************************************************************************
 * Private include files
 ****************************************************************************************************************/

#include "standard_muckle.hpp"

/****************************************************************************************************************
 * Private methods/functions implementation
 ****************************************************************************************************************/

void key_exchange_MUCKLE::mac_sign(const uint8_t *msg, const size_t msg_len, const uint8_t *k, const size_t k_len, uint8_t *tag)
{
    auto mac = Botan::MessageAuthenticationCode::create_or_throw(hmac_botan_primitive_names[mac_prim]); // create an instance of a mac
    mac->set_key(span<const uint8_t>(k, k_len));                                                        // set the key
    mac->update(span<const uint8_t>(msg, msg_len));
    Botan::secure_vector<uint8_t> tag_v = mac->final(); // create the tag
    copy(tag_v.begin(), tag_v.begin() + mac_trunc, tag);
}

bool key_exchange_MUCKLE::ct_cmp(const uint8_t *array1, const uint8_t *array2, size_t length)
{
    // Initialize the result variable to zero.
    // This variable will accumulate the differences between the arrays.
    uint8_t result = 0;

    // Iterate through each byte of the arrays.
    for (size_t i = 0; i < length; ++i)
    {
        // Use XOR to compare the bytes and accumulate the differences.
        result |= array1[i] ^ array2[i];
    }

    // The result will be 0 if and only if all bytes are equal.
    // If there is any difference, the result will be non-zero.
    return result == 0;
}

int key_exchange_MUCKLE::mac_verify(const uint8_t *msg, const size_t msg_len, const uint8_t *k, const size_t k_len, const uint8_t *tag)
{
    uint8_t aux_tag[32];                                                                                // auxiliar tag to compare with the recived tag
    auto mac = Botan::MessageAuthenticationCode::create_or_throw(hmac_botan_primitive_names[mac_prim]); // create an instance of a mac
    mac->set_key(span<const uint8_t>(k, k_len));                                                        // set the key
    mac->update(span<const uint8_t>(msg, msg_len));
    Botan::secure_vector<uint8_t> tag_v = mac->final(); // create the tag
    copy(tag_v.begin(), tag_v.begin() + mac_trunc, aux_tag);
    return ct_cmp(tag, aux_tag, mac_trunc);
}

void key_exchange_MUCKLE::prf(const uint8_t *k, const uint8_t *in_buff, size_t in_buff_len, uint8_t *out_buff)
{
    // A constant random salt for the Key Derivation Function (KDF)
    const uint8_t salt[32] = {0x50, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x6f,
                              0x20, 0x65, 0x73, 0x20, 0x6c, 0x61, 0x20, 0x76,
                              0x69, 0x72, 0x74, 0x75, 0x64, 0x20, 0x65, 0x6e,
                              0x20, 0x61, 0x63, 0x63, 0x69, 0xf3, 0x6e, 0x2e}; // just a random salt constant for the KDF

    // Create a Key Derivation Function (KDF) object using Botan
    auto kdf = Botan::KDF::create_or_throw(prf_botan_primitive_names[prf_prim]);

    // Derive a key using the KDF with the provided key, salt, and input buffer
    auto out = kdf->derive_key(SK_SZ, span<const uint8_t>(k, SK_SZ), span<const uint8_t>(salt, sizeof(salt)), span<const uint8_t>(in_buff, in_buff_len));

    // Copy the derived key to the output buffer
    copy(out.begin(), out.end(), out_buff);
}

/****************************************************************************************************************
 * Public methods implementation
 ****************************************************************************************************************/

key_exchange_MUCKLE::key_exchange_MUCKLE(uint8_t rol, uint8_t *s_id, uint8_t *p_id, unsigned char *l_A, unsigned char *l_B, unsigned char *l_CKEM, unsigned char *l_QKEM, uint8_t *sec_st, uint8_t *psk, mac_primitive mac_prim, uint16_t mac_trunc, prf_primitive prf_prim, prf_primitive kdf_prim, elliptic_curve ecdh_c, ml_kem qkem_mode)
{
    // parameter checking, if invalid rol or invalid primitives, throw exception
    if (rol > 1 || l_A == nullptr || l_B == nullptr || l_CKEM == nullptr || l_QKEM == nullptr || sec_st == nullptr || psk == nullptr || mac_prim >= mac_primitive_size ||
        mac_trunc > 256 || prf_prim >= prf_primitive_size || kdf_prim >= prf_primitive_size || ecdh_c >= elliptic_curve_types_size || qkem_mode >= ml_kem_enum_size)
        throw invalid_argument("Incorrect input parameters on MUCKLE construction");

    // assign input data to the object, and set attributes as initialized
    this->rol = rol;
    memcpy(this->s_id, s_id, ID_SZ);
    memcpy(this->p_id, p_id, ID_SZ);
    // copy the labels of this instantiation protocol
    memcpy(this->l_A, l_A, LABEL_SZ);
    memcpy(this->l_B, l_B, LABEL_SZ);
    memcpy(this->l_CKEM, l_CKEM, LABEL_SZ);
    memcpy(this->l_QKEM, l_QKEM, LABEL_SZ);

    // copy Critical Security Parameters
    memcpy(this->sec_st, sec_st, SECST_SZ);
    memcpy(this->psk, psk, PSK_SZ);

    // instanciate the selected cryptographic primitives
    this->mac_prim = mac_prim;
    this->mac_trunc = mac_trunc / 8; //put it in bytes
    this->prf_prim = prf_prim;
    this->kdf_prim = kdf_prim;
    this->ecdh_c = ecdh_c;
    this->qkem_mode = qkem_mode;

    // build first instance atributes
    this->com_st = void_com;
    this->sk_st = SK_NOT_REVEALED;

    // build header
    uint16_t itr = 0;
    this->header[itr++] = this->rol;
    memcpy(this->header + itr, &this->mac_prim, sizeof(this->mac_prim));
    itr += sizeof(this->mac_prim);
    memcpy(this->header + itr, &this->prf_prim, sizeof(this->prf_prim));
    itr += sizeof(this->prf_prim);
    memcpy(this->header + itr, &this->kdf_prim, sizeof(this->prf_prim));
    itr += sizeof(this->prf_prim);
    memcpy(this->header + itr, &this->ecdh_c, sizeof(this->ecdh_c));
    itr += sizeof(this->ecdh_c);
    memcpy(this->header + itr, &this->qkem_mode, sizeof(this->qkem_mode));
    itr += sizeof(this->qkem_mode);
    memcpy(this->header + itr, this->s_id, ID_SZ);
    itr += ID_SZ;
    if (itr != HEADER_SZ)
        throw invalid_argument("Incorrect input parameters on header construction");

    // Create the private keys for both KEMs using dynamic memory with unique ptrs since botan developers decided "why would a programmer instantiate an uninitialized private key"
    Botan::AutoSeeded_RNG rng; // Rng for random key generation

    // Create an instance of the selected elliptic curve, and a random number generator for EC Diffie-Hellman(both initializer and responder)
    const auto curve = Botan::EC_Group::from_name(elliptic_curve_names[ecdh_c]);
    ckem_priv_k = make_unique<Botan::ECDH_PrivateKey>(rng, curve);

    //If the role of the entity if an initializer, generate a private ml_kem key
    if (this->rol == INITIALIZER)
    {
        // Usereate a Private ML_KEM key, and generate the corresponding public key
        const auto rand = rng.random_array<16>();
        if (this->qkem_mode == ml_kem_128) // ml_kem with 128 bits security
            qkem_priv_k = make_unique<Botan::ML_KEM_PrivateKey>(rng, Botan::ML_KEM_Mode::ML_KEM_512);
        else if (this->qkem_mode == ml_kem_192) // ml_kem with 192 bits security
            qkem_priv_k = make_unique<Botan::ML_KEM_PrivateKey>(rng, Botan::ML_KEM_Mode::ML_KEM_768);
        else // ml_kem with 256 bits security
            qkem_priv_k = make_unique<Botan::ML_KEM_PrivateKey>(rng, Botan::ML_KEM_Mode::ML_KEM_1024);
    }
}

key_exchange_MUCKLE::~key_exchange_MUCKLE()
{
    // Simply secure zeroize the critical security parameters
    secure_zeroize(this->psk, PSK_SZ);
    secure_zeroize(this->sec_st, SECST_SZ);
    secure_zeroize(this->sk, SK_SZ);
    secure_zeroize(this->psk, PSK_SZ);
    secure_zeroize(this->macsign_k, SK_SZ);
    secure_zeroize(this->csk, SK_SZ);
    secure_zeroize(this->qsk, SK_SZ);
    for(int i = 0 ; i < 4 ; i++){
        secure_zeroize(this->chain_k[i],SK_SZ);
    }
    // Zeroize labels, but idk if this is necessary, probably not
    secure_zeroize(this->l_A, LABEL_SZ);
    secure_zeroize(this->l_B, LABEL_SZ);
    secure_zeroize(this->l_CKEM, LABEL_SZ);
    secure_zeroize(this->l_QKEM, LABEL_SZ);
}

return_code key_exchange_MUCKLE::send_m0(unique_ptr<uint8_t[]> &buffer_out, size_t &out_buff_len)
{
    if (rol != INITIALIZER)
        return return_code::INCORRECT_ROL_OPERATION;
    com_st = running_com;
    sk_st = SK_NOT_REVEALED;

    // get public keys with black magic of pointers
    const auto ckey_pub = ckem_priv_k.get()->public_value();
    const auto qkey_pub = qkem_priv_k.get()->public_key();

    // BER encode ML_KEM public keys
    vector<uint8_t> serialized_qkey_pub = Botan::X509::BER_encode(*qkey_pub.get()); // serialize qkey in BER format with some black magic of pointers

    // Calculate serialized keys len
    auto serialized_ckey_pub_len = ckey_pub.size();
    auto serialized_qkey_pub_len = serialized_qkey_pub.size();

    // Calculate mac signing key
    prf(psk, sec_st, SECST_SZ, macsign_k);
    prf(macsign_k, l_A, LABEL_SZ, macsign_k);

    // Allocate the output buffer
    out_buff_len = HEADER_SZ + sizeof(size_t) + serialized_ckey_pub_len + sizeof(size_t) + serialized_qkey_pub_len + mac_trunc;
    try
    {
        buffer_out = make_unique<uint8_t[]>(out_buff_len); // setup the required length to store-> header_a||size_ckey_pub||ckey_pub||size_qkey_pub||qkey_pub||mac_tag
    }
    catch (const bad_alloc &e)
    {
        cerr << "Memory allocation error: " << e.what() << endl;
        this->com_st = rejected_com;
        return return_code::MEMORY_ALLOCATION_FAIL; // Return memory allocation failure
    }

    // Construct the buffer to sign
    size_t itr = 0;
    copy(header, header + HEADER_SZ, buffer_out.get()); // copy the header
    itr += HEADER_SZ;
    copy(reinterpret_cast<const uint8_t *>(&serialized_ckey_pub_len), reinterpret_cast<const uint8_t *>(&serialized_ckey_pub_len) + sizeof(serialized_ckey_pub_len), buffer_out.get() + itr); // copy the len of ckey_pub
    itr += sizeof(serialized_ckey_pub_len);
    copy(reinterpret_cast<const uint8_t *>(&ckey_pub), reinterpret_cast<const uint8_t *>(&ckey_pub) + serialized_ckey_pub_len, buffer_out.get() + itr); // copy ckey_pub
    itr += serialized_ckey_pub_len;
    copy(reinterpret_cast<const uint8_t *>(&serialized_qkey_pub_len), reinterpret_cast<const uint8_t *>(&serialized_qkey_pub_len) + sizeof(serialized_qkey_pub_len), buffer_out.get() + itr); // copy the len of qkey_pub
    itr += sizeof(serialized_qkey_pub_len);
    copy(reinterpret_cast<const uint8_t *>(&serialized_qkey_pub), reinterpret_cast<const uint8_t *>(&serialized_qkey_pub) + serialized_qkey_pub_len, buffer_out.get() + itr); // copy qkey_pub
    itr += serialized_qkey_pub_len;

    // sign the buffer with the choosen mac signing algorithm
    mac_sign(buffer_out.get(), itr, macsign_k, SK_SZ, buffer_out.get() + itr);

    return return_code::MUCKLE_OK;
}