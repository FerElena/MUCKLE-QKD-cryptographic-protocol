/**
 * @file standard_muckle.h
 * @brief File containing the header of the implementation of the Muckle protocol, used for key exchange in the context of hybrid protocols.
 *
 * Muckle securely combines keying material obtained from a quantum key distribution (QKD) protocol
 * with that from a post-quantum-secure key encapsulation mechanism(KEM) and a classically-secure KEM,
 * and uses it as the basis for authenticating its protocol messages via MACs.
 *
 * the QKD protocol is not implemented here, the keys transmitted by QKD are expected to be inserted externally into the class
 *
 * @author Fernando Elena Benavente , felena@oesia.com
 *
 * @details the protocol is described in detail in the publication paper: https://eprint.iacr.org/2020/099.pdf
 *
 */

#ifndef STANDARD_MUCKLE_H
#define STANDARD_MUCKLE_H

/****************************************************************************************************************
 * Include files
 ****************************************************************************************************************/

#include <cstdint>
#include <string>
#include <cstring>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/ml_kem.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>

using namespace std;

/****************************************************************************************************************
 * Global variables/constants/enums definition
 ****************************************************************************************************************/

 // Roles of the communicator
const uint8_t INITIALIZER = 0;
const uint8_t RESPONDER = 1;


/**
 * @brief enum representing the allowed MAC functions for the protocol used as MAC, a minimum length of 256 hash length is required to be secure
 *
 */
typedef enum mac_primitive : unsigned short
{
    hmac256_sha2_256,
    hmac256_sha2_384,
    hmac256_sha2_512,
    hmac256_sha3_256,
    hmac256_sha3_384,
    hmac256_sha3_512,
    kmac256,
    cmac_256,
    mac_primitive_size // size of the enum
} mac_primitive;

/**
 * @brief string array representing the required botan format for calling of a MAC function
 *
 */
const string hmac_botan_primitive_names[mac_primitive_size] = {
    "HMAC(SHA-256)",
    "HMAC(SHA-384)",
    "HMAC(SHA-512)",
    "HMAC(SHA-3(256))",
    "HMAC(SHA-3(384))",
    "HMAC(SHA-3(512))",
    "KMAC-256(256)",
    "CMAC(AES-256)"
};

/**
 * @brief enum representing the key derivation function (KDF) used as a PRF in the Muckle protocol
 */
typedef enum prf_primitive : unsigned short
{
    hkdf_sha2_256,
    hkdf_sha2_384,
    hkdf_sha2_512,
    hkdf_sha3_256,
    hkdf_sha3_384,
    hkdf_sha3_512,
    kdf2_sha2_256,
    kdf2_sha2_384,
    kdf2_sha2_512,
    kdf2_sha3_256,
    kdf2_sha3_384,
    kdf2_sha3_512,
    sp800_56a_sha2_256,
    sp800_56a_sha2_384,
    sp800_56a_sha2_512,
    sp800_56a_sha3_256,
    sp800_56a_sha3_384,
    sp800_56a_sha3_512,
    sp800_56c_sha2_256,
    sp800_56c_sha2_384,
    sp800_56c_sha2_512,
    sp800_56c_sha3_256,
    sp800_56c_sha3_384,
    sp800_56c_sha3_512,
    prf_primitive_size // size of the enum
} prf_primitive;

/**
 * @brief string array representing the required botan format for calling of a KDF function
 *
 */
const string prf_botan_primitive_names[prf_primitive_size] = {
    "HKDF(HMAC(SHA-256))",
    "HKDF(HMAC(SHA-384))",
    "HKDF(HMAC(SHA-512))",
    "HKDF(HMAC(SHA-3(256))",
    "HKDF(HMAC(SHA-3(384))",
    "HKDF(HMAC(SHA-3(512))",
    "KDF2(SHA256)",
    "KDF2(SHA384)",
    "KDF2(SHA512)",
    "KDF2(SHA-3(256))",
    "KDF2(SHA-3(384))",
    "KDF2(SHA-3(512))",
    "SP800-56A(HMAC(SHA-256))",
    "SP800-56A(HMAC(SHA-384))",
    "SP800-56A(HMAC(SHA-512))",
    "SP800-56A(HMAC(SHA-3(256))",
    "SP800-56A(HMAC(SHA-3(384))",
    "SP800-56A(HMAC(SHA-3(512))",
    "SP800-56C(HMAC(SHA-256))",
    "SP800-56C(HMAC(SHA-384))",
    "SP800-56C(HMAC(SHA-512))",
    "SP800-56C(HMAC(SHA-3(256))",
    "SP800-56C(HMAC(SHA-3(384))",
    "SP800-56C(HMAC(SHA-3(512))",
};

/**
 * @brief enum representing the supported curves for Elliptic Curve Diffie-Hellman
 */
typedef enum elliptic_curve : unsigned short
{
    secpk256r1_curve,
    secp384r1_curve,
    secp521r1_curve,
    brainpool256r1,
    brainpool384r1,
    brainpool512r1,
    x25519,
    x448,
    elliptic_curve_types_size // size of the enum
} elliptic_curve;

/**
 * @brief string array representing the required botan format for calling the curves for Elliptic Curve Diffie-Hellman
 *
 */
const string elliptic_curve_names[elliptic_curve_types_size] = {
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "brainpool256r1",
    "brainpool384r1",
    "brainpool512r1",
    "x25519",
    "x448"
};

/**
 * @brief pattern used for secure data zeroization
 *
 */
static const unsigned char Schneier_patterns[6] = {0x00, 0xFF, 0xAA, 0x55, 0xAA, 0x55};

/**
 * @brief function used for secure byte data zeroization
 */
inline void secure_zeroize(void *data, size_t data_len)
{
    uint8_t* iterator = static_cast<uint8_t*>(data);
    for (int i = 0; i < sizeof(Schneier_patterns); i++)
    {
        for (int j = 0; j < data_len; iterator[j++] = Schneier_patterns[i])
            ;
    }
}

/**
 * @brief function used for secure vector zeroization
 */
inline void secure_zeroize_vector(std::vector<uint8_t> &vec)
{
    secure_zeroize(vec.data(), vec.size());
}

/****************************************************************************************************************
 * class definition
 ****************************************************************************************************************/

class key_exchange_MUCKLE
{
private:
    /////////////////////////// attributes ///////////////////////////

    uint8_t rol;                              ///< Rol of the communicator, it can be a INITIALIZER, or a RESPONDER
    unsigned char l_A[32];                    ///< Initializer label used in the PRF (represented as A in the original paper)
    unsigned char l_B[32];                    ///< Responder label used in the PRF (represented as B in the original paper)
    unsigned char l_CKEM[32];                 ///< Label used in the PRF to derive the classical key (refered as ck in the paper)
    unsigned char l_QKEM[32];                 ///< Label used in the PRF to derive the quantum key (refered as qk in the paper)
    uint8_t sec_st[32];                       ///< Current secret state of the Muckle protocol (refered as SecState in the paper) 256 bit len
    uint8_t psk[32];                          ///< Pre-shared Symmetric Keys that must be instanciated in the initialization (refered as PSK in the paper) 256 bits len
    mac_primitive mac_prim;                   ///< MAC primitive that is going to be used in this instance of the protocol
    uint16_t mac_trunc;                       ///< MAC tag truncation
    prf_primitive prf_prim;                   ///< Pseudo Random Function (PRF) that is going to be used in this instance of the protocol
    prf_primitive kdf_prim;                   ///< Key derivation function used to derive the key in the classic and post-quantum KEM
    elliptic_curve ecdh_prim;                 ///< Elliptic curve that will be utilized in the ECDH key exchange

    /* the private and public keys of asymmetric cryptography cannot be crypto-agile, since in the botan library and most libraries are defined with a specific structure for 
    the algorithm,because they are not simply a stream of bits in an array, but an object representing mathematical properties specific to the algorithm, so currently
    this implementation of the Muckle protocol only supports ECDH as classical KEM, and ML_KEM (Kyber currently) as post-quantum kem, in the future, cryptoagility
    for kem implementations should be implemented, but idk how to do it without a mess of a code with the current BOTAN API*/

    Botan::ECDH_PrivateKey priv_ecdh_k;       ///< Elliptic Curve Diffie Hellman key exchange instanciation
    Botan::ML_KEM_PrivateKey priv_kyber_k;    ///< ML_KEM priv key for the use of Kyber 

    
    
};

#endif