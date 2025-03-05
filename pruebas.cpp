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

void printHex(const unsigned char *buffer, size_t size)
{
   for (size_t i = 0; i < size; ++i)
   {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
      if (i % 16 == 15)
      {
         std::cout << std::endl;
      }
      else
      {
         std::cout << ' ';
      }
   }
   std::cout << std::dec << std::endl;
}

int main()
{
   //ECDH
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

   //Kyber
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

   return 0;
}