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

void key_exchange_MUCKLE::prf(const uint8_t *k, const uint8_t *in_buff, size_t in_buff_len, uint8_t out_buff)
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

 key_exchange_MUCKLE::key_exchange_MUCKLE(uint8_t rol, uint8_t *s_id, uint8_t *p_id, unsigned char *l_A, unsigned char *l_B, unsigned char *l_CKEM, unsigned char *l_QKEM,
    uint8_t *sec_st, uint8_t *psk, mac_primitive mac_prim, uint16_t mac_trunc, prf_primitive prf_prim, prf_primitive kdf_prim, elliptic_curve ecdh_c)
{
    // parameter checking, if invalid rol or invalid primitives, throw exception
    if(rol > 1 || l_A == nullptr || l_B == nullptr || l_CKEM == nullptr || l_QKEM = nullptr || sec_st == nullptr || psk == nullptr ||
         mac_prim >= mac_primitive_size || mac_trunc > 256|| prf_prim >= prf_primitive_size || kdf_prim >=prf_primitive_size || ecdh_c >= elliptic_curve_types_size )
         throw invalid_argument("Incorrect input parameters on MUCKLE construction");

    // assign input data to the object, and set attributes as initialized
    this->rol = rol;
    memcpy(this->s_id,s_id,ID_SZ);
    memcpy(this->p_id,p_id,ID_SZ);
    //copy the labels of this instantiation protocol
    memcpy(this->l_A,l_A,LABEL_SZ);
    memcpy(this->l_B,l_B,LABEL_SZ);
    memcpy(this->l_CKEM,l_CKEM,LABEL_SZ);
    memcpy(this->l_QKEM,l_QKEM,LABEL_SZ);

    //copy Critical Security Parameters
    memcpy(this->sec_st,sec_st,SECST_SZ);
    memcpy(this->psk,psk,PSK_SZ);

    //instanciate the selected cryptographic primitives
    this->mac_prim = mac_prim;
    this->mac_trunc = mac_trunc;
    this->prf_prim = prf_prim;
    this->kdf_prim = kdf_prim;
    this->ecdh_c = ecdh_c;

    //build first instance atributes
    this->com_st = void_com;
    this->sk_st = SK_NOT_REVEALED;
    uint16_t itr = 0;
    this->header[itr++] = this->rol;
    memcpy(this->header + itr,this->mac_prim,sizeof(this->mac_prim));
    itr+=sizeof(this->mac_prim);
    memcpy(this->header + itr,this->prf_prim,sizeof(this->prf_prim));
    itr+=sizeof(this->prf_prim);
    memcpy(this->header + itr,this->kdf_prim,sizeof(this->prf_prim));
    itr+=sizeof(this->prf_prim);
    memcpy(this->header + itr,this->ecdh_c,sizeof(this->ecdh_c));
    itr+=sizeof(this->ecdh_c);
    memcpy(this->header + itr,this->s_id,ID_SZ);
    itr+=ID_SZ;
    if(itr != HEADER_SZ)
    throw invalid_argument("Incorrect input parameters on MUCKLE construction");
}
