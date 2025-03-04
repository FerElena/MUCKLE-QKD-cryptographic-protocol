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
#include <botan/hex.h>
#include <botan/system_rng.h>

using namespace std;

/****************************************************************************************************************
* Global variables/constants/enums definition
****************************************************************************************************************/



/****************************************************************************************************************
* class definition
****************************************************************************************************************/

#endif