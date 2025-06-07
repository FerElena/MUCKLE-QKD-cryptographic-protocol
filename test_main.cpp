// g++ -std=c++20 test_main.cpp standard_muckle.cpp -I /usr/local/include/botan-3 -L /usr/local/lib -lbotan-3 -o test_main

#include <iostream>
#include <iomanip>

#include "standard_muckle.hpp"

using namespace std;

////////////////////////////////////////////ONLY FOR TEST FUNCTION////////////////////////////////////////////
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
////////////////////////////////////////////ONLY FOR TEST FUNCTION////////////////////////////////////////////

int main()
{
   //  muckle protocol test

   // labels
   uint8_t l_A[32] = {0};
   uint8_t l_B[32] = {0};
   uint8_t l_ckem[32] = {0};
   uint8_t l_qkem[32] = {0};

   // info
   uint8_t i_id[32] = {0xFF, 0x95, 0xA7, 0x0F, 0x89, 0xCA, 0x0E, 0x3D, // initializer id
                       0x7A, 0xB6, 0x23, 0x8C, 0x5E, 0xD4, 0xFF, 0x12,
                       0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0x38, 0x81, 0xBC,
                       0x7D, 0xC9, 0x01, 0xF4, 0x56, 0xAA, 0xEF, 0x56};
   uint8_t r_id[32] = {0xFF, 0x95, 0xA7, 0x0F, 0x89, 0xCA, 0x0E, 0x3D, // responder id
                       0x7A, 0xB6, 0x23, 0x8C, 0x5E, 0xD4, 0xFF, 0x12,
                       0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0x38, 0x81, 0xBC,
                       0x7D, 0xC9, 0x01, 0xF4, 0x56, 0xAA, 0xEF, 0x56};

   // secret info
   uint8_t sec_state[32] = {0x32, 0x75, 0xAB, 0x4F, 0x91, 0xCA, 0x0E, 0x3D, // secret state
                            0x7A, 0xB6, 0x23, 0x8C, 0x5E, 0xD4, 0xFF, 0x12,
                            0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0x38, 0x81, 0xBC,
                            0x7D, 0xC9, 0x01, 0xF4, 0x56, 0xAA, 0xEF, 0x34};

   uint8_t psk[32] = {0xFF, 0x95, 0xA7, 0x0F, 0x89, 0xCA, 0x0E, 0x3D, // pre-shared key
                      0x7A, 0xB6, 0x23, 0x8C, 0x5E, 0xD4, 0xFF, 0x12,
                      0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0x38, 0x81, 0xBC,
                      0x7D, 0xC9, 0x01, 0xF4, 0x56, 0xAA, 0xEF, 0x56};

   uint8_t qkd_key[32] = {0xFF, 0x97, 0xA7, 0x0F, 0x89, 0xCA, 0x0E, 0x3D, // key form the QKD network
                          0x7A, 0xB6, 0x23, 0xEC, 0x5E, 0xD4, 0xFF, 0x12,
                          0x6B, 0xA3, 0x9F, 0x45, 0xE2, 0xBB, 0x81, 0xBC,
                          0x7D, 0xC9, 0xF1, 0xF4, 0x56, 0xAA, 0xEF, 0x56};

   unique_ptr<uint8_t[]> buffer_1, buffer_2;
   size_t buffer_1_length, buffer_2_length;

   key_exchange_MUCKLE muckle_initializer(INITIALIZER, i_id, r_id, l_A, l_B, l_ckem, l_qkem, sec_state, psk, hmac256_sha3_256, 256, hkdf_sha2_256, hkdf_sha2_256, secpk256r1_curve, ml_kem_256);
   key_exchange_MUCKLE muckle_responder(RESPONDER, r_id, i_id, l_A, l_B, l_ckem, l_qkem, sec_state, psk, hmac256_sha3_256, 256, hkdf_sha2_256, hkdf_sha2_256, secpk256r1_curve, ml_kem_256);

   int result = (int)muckle_initializer.send_m0(buffer_1, buffer_1_length);
   cout << "the length of m0 is : " << buffer_1_length << endl;
   cout << "operation result is : " << result << endl;

   result = (int)muckle_responder.recive_m0_send_m1(move(buffer_1), buffer_1_length, buffer_2, buffer_2_length);
   cout << "the length of m0 is : " << buffer_2_length << endl;
   cout << "operation result is :: " << result << endl;

   result = (int)muckle_initializer.recive_m1(move(buffer_2), buffer_2_length);
   cout << "operation result is : " << result << endl;

   muckle_initializer.update_state(qkd_key);
   muckle_responder.update_state(qkd_key);

   uint8_t sk_a[32];
   uint8_t sk_b[32];

   muckle_initializer.get_sk(sk_a);
   muckle_responder.get_sk(sk_b);

   if (!memcmp(sk_a, sk_b, 32))
      cout << "both shared keys are equal!!!!" << endl;
   else
      cout << "error, shared keys differ" << endl;

   cout << "Initializer key is: \n";
   printHex(sk_a, 32);
   cout << "Responder key is : \n";
   printHex(sk_b, 32);

   // prueba a varias iteraciones de ejecución del protocolo
   for (int i = 0; i < 100000; i++)
   {
      result = (int)muckle_initializer.send_m0(buffer_1, buffer_1_length);
      result = (int)muckle_responder.recive_m0_send_m1(move(buffer_1), buffer_1_length, buffer_2, buffer_2_length);
      result = (int)muckle_initializer.recive_m1(move(buffer_2), buffer_2_length);

      muckle_initializer.update_state(qkd_key);
      muckle_responder.update_state(qkd_key);

      muckle_initializer.get_sk(sk_a);
      muckle_responder.get_sk(sk_b);

      if (!memcmp(sk_a, sk_b, 32))
      {
         if (i % 10000 == 0 && i != 0)
            cout << "both keys are equal after  " << i <<" iterations !!!!" << endl;
      }
      else
         cout << "fail in iteration  :" << i << endl;
   }

   return 0;
}

