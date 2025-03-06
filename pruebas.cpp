// g++ -std=c++20 -I /usr/local/include/botan-3 pruebas.cpp standard_muckle.cpp -L /usr/local/lib -Wl,--start-group -lbotan-3 -Wl,--end-group -o prueba

#include <iostream>
#include <iomanip>
#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>
#include <botan/data_src.h>
#include <botan/kdf.h>
#include <botan/ml_kem.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>

#include "standard_muckle.hpp"

using namespace std;

int main()
{
   // ECDH
   Botan::AutoSeeded_RNG rng;

   // ec domain and KDF
   const auto domain = Botan::EC_Group::from_name("secp521r1");
   const std::string kdf = "KDF2(SHA-256)";

   // the two parties generate ECDH keys
   Botan::ECDH_PrivateKey key_a(rng, domain);
   Botan::ECDH_PrivateKey key_b(rng, domain);

   // now they exchange their public values
   const auto key_apub = key_a.public_value();
   const auto key_bpub = key_b.public_value();

   // Construct key agreements and agree on a shared secret
   Botan::PK_Key_Agreement ka_a(key_a, rng, kdf);
   const auto sA = ka_a.derive_key(32, key_bpub).bits_of();

   Botan::PK_Key_Agreement ka_b(key_b, rng, kdf);
   const auto sB = ka_b.derive_key(32, key_apub).bits_of();

   if (sA != sB)
   {
      return 1;
   }

   std::cout << "agreed key DHEC:\n"
             << Botan::hex_encode(sA) << endl;

   // Kyber
   const size_t shared_key_len = 32;

   const auto salt = rng.random_array<16>();

   Botan::ML_KEM_PrivateKey priv_key(rng, Botan::ML_KEM_Mode::ML_KEM_768);
   auto pub_key = priv_key.public_key();

   Botan::PK_KEM_Encryptor enc(*pub_key, kdf);

   const auto kem_result = enc.encrypt(rng, shared_key_len, salt);

   Botan::PK_KEM_Decryptor dec(priv_key, rng, kdf);

   auto dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), shared_key_len, salt);

   if (dec_shared_key != kem_result.shared_key())
   {
      std::cerr << "Shared keys differ\n";
      return 1;
   }

   std::cout << "agreed key KYBER:\n"
             << Botan::hex_encode(dec_shared_key) << endl;

   // actual muckle protocol test

   uint8_t l_A[32] = {0};
   uint8_t l_B[32] = {0};
   uint8_t l_ckem[32] = {0};
   uint8_t l_qkem[32] = {0};
   uint8_t sec_state[32] = {0x32, 0x75, 0xAB, 0x4F, 0x91, 0xCA, 0x0E, 0x3D,
                            0x7A, 0xB6, 0x23, 0x8C, 0x5E, 0xD4, 0xFF, 0x12,
                            0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0x38, 0x81, 0xBC,
                            0x7D, 0xC9, 0x01, 0xF4, 0x56, 0xAA, 0xEF, 0x34};
   uint8_t psk[32] = {0xFF, 0x95, 0xA7, 0x0F, 0x89, 0xCA, 0x0E, 0x3D,
                      0x7A, 0xB6, 0x23, 0x8C, 0x5E, 0xD4, 0xFF, 0x12,
                      0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0x38, 0x81, 0xBC,
                      0x7D, 0xC9, 0x01, 0xF4, 0x56, 0xAA, 0xEF, 0x56};
   uint8_t i_id[32] = {0xFF, 0x95, 0xA7, 0x0F, 0x89, 0xCA, 0x0E, 0x3D,
                       0x7A, 0xB6, 0x23, 0x8C, 0x5E, 0xD4, 0xFF, 0x12,
                       0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0x38, 0x81, 0xBC,
                       0x7D, 0xC9, 0x01, 0xF4, 0x56, 0xAA, 0xEF, 0x56};
   uint8_t r_id[32] = {0xFF, 0x95, 0xA7, 0x0F, 0x89, 0xCA, 0x0E, 0x3D,
                       0x7A, 0xB6, 0x23, 0x8C, 0x5E, 0xD4, 0xFF, 0x12,
                       0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0x38, 0x81, 0xBC,
                       0x7D, 0xC9, 0x01, 0xF4, 0x56, 0xAA, 0xEF, 0x56};
   uint8_t qkd_key[32] = {0xFF, 0x97, 0xA7, 0x0F, 0x89, 0xCA, 0x0E, 0x3D,
                          0x7A, 0xB6, 0x23, 0xEC, 0x5E, 0xD4, 0xFF, 0x12,
                          0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0xBB, 0x81, 0xBC,
                          0x7D, 0xC9, 0xF1, 0xF4, 0x56, 0xAA, 0xEF, 0x56};

   unique_ptr<uint8_t[]> buffer_1, buffer_2;
   size_t buffer_1_length, buffer_2_length;

   key_exchange_MUCKLE muckle_initializer(INITIALIZER, i_id, r_id, l_A, l_B, l_ckem, l_qkem, sec_state, psk, hmac256_sha3_256, 256, hkdf_sha2_256, hkdf_sha2_256, secpk256r1_curve, ml_kem_256);
   key_exchange_MUCKLE muckle_responder(RESPONDER, r_id, i_id, l_A, l_B, l_ckem, l_qkem, sec_state, psk, hmac256_sha3_256, 256, hkdf_sha2_256, hkdf_sha2_256, secpk256r1_curve, ml_kem_256);

   int result = (int)muckle_initializer.send_m0(buffer_1, buffer_1_length);
   cout << "la longitud de m0 es : " << buffer_1_length << endl;
   cout << "el resultado de la operacion es: " << result << endl;

   result = (int)muckle_responder.recive_m0_send_m1(move(buffer_1), buffer_1_length, buffer_2, buffer_2_length);
   cout << "la longitud de m0 es : " << buffer_2_length << endl;
   cout << "el resultado de la operacion es: " << result << endl;

   result = (int)muckle_initializer.recive_m1(move(buffer_2), buffer_2_length);
   cout << "el resultado de la operacion es: " << result << endl;

   muckle_initializer.update_state(qkd_key);
   muckle_responder.update_state(qkd_key);
   return 0;
}