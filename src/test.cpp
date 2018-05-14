#include <stdlib.h>
#include <iostream>

#include "snark.hpp"
#include "test.h"

#include <boost/optional/optional_io.hpp> // for cout<<proof --Agzs

using namespace libsnark;
using namespace std;

int main()
{
    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();
    // Generate the verifying/proving keys. (This is trusted setup!)
    auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

    // Run test vectors.
    assert(run_test(keypair, false, false, false));   // 正确的例子，必须保证是xor，以及生成和验证proof时r_i与h_i间的对应关系
    //assert(!run_test(keypair, true, false, false)); // 错误的例子，用and替换xor
    //assert(!run_test(keypair, false, true, false)); // 错误的例子，交换r1和r2
    //assert(!run_test(keypair, false, false, true)); // 错误的例子，交换h1和h2
}

bool run_test(r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp>& keypair,
              // These are just for changing behavior
              // for testing purposes:
              bool use_and_instead_of_xor,
              bool swap_r1_r2,
              bool goofy_verification_inputs
    ) {

    // Initialize bit_vectors for all of the variables involved.
    std::vector<bool> h1_bv(256); // h1_bv = sha256(r1_bv), known
    std::vector<bool> h2_bv(256); // h2_bv = sha256(r2_bv), known
    std::vector<bool> x_bv(256);  // known
    std::vector<bool> r1_bv(256); // r1_bv = r2_bv xor x, unknown
    std::vector<bool> r2_bv(256); // unknown --Agzs

    {
        /* These are working test vectors.  --Agzs
         ******************************************************************* --Agzs
         * r1_bv = r2_bv xor x_bv  = 0xb422faa6c8b1f089ccdbb21122e4241cb6bf108dd249884188983c75186512
         * h1_bv = sha256(r1_bv)   = 0xa9e760bdddeaf055d5bbec7264b98256e71d7bc439e19fd822be7b61e39b478
         * x_bv  = sha256("LAB")   = 0x7a62e3ac3d7c6e27346c0a41d261dc7cdb46d3b7ed89073b770982923da14c
         * r2_bv = sha256("SCIPR") = 0xce4019af5cdf66bbf9d72b53f285f866b2d22bf3ad9fbf6f801556c2645e
         * h2_bv = sha256(r2_bv)   = 0xfdc74237189b50798a3c24c9badda441c235c09ffc7c218c8d939372dcc479
         * 
         * r2_bv = sha256("SCIPR")    
         * x_bv = sha256("LAB")
         * r1_bv = r2_bv xor x_bv
         * 
         * Note: the para of sha256() is [u8] type, and the string converts to this type
         ************************************************************************
        */
        h1_bv = int_list_to_bits({169, 231, 96, 189, 221, 234, 240, 85, 213, 187, 236, 114, 100, 185, 130, 86, 231, 29, 123, 196, 57, 225, 159, 216, 34, 190, 123, 97, 14, 57, 180, 120}, 8);
        h2_bv = int_list_to_bits({253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164, 65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9}, 8);
        x_bv = int_list_to_bits({122, 98, 227, 172, 61, 124, 6, 226, 115, 70, 192, 164, 29, 38, 29, 199, 205, 180, 109, 59, 126, 216, 144, 115, 183, 112, 152, 41, 35, 218, 1, 76}, 8);
        r1_bv = int_list_to_bits({180, 34, 250, 166, 200, 177, 240, 137, 204, 219, 178, 17, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
        r2_bv = int_list_to_bits({206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94}, 8);
    }

    if (use_and_instead_of_xor) { 
        // This uses AND instead of XOR, which should properly test // r1 = r2 AND x --Agzs
        // the XOR constraint of the circuit.
        h1_bv = int_list_to_bits({245, 151, 92, 200, 120, 203, 58, 116, 216, 30, 82, 196, 179, 104, 132, 100, 64, 99, 99, 177, 160, 94, 193, 168, 186, 225, 224, 143, 97, 77, 135, 115}, 8);
        h2_bv = int_list_to_bits({253, 199, 66, 55, 24, 155, 80, 121, 138, 60, 36, 201, 186, 221, 164, 65, 194, 53, 192, 159, 252, 7, 194, 24, 200, 217, 57, 55, 45, 204, 71, 9}, 8);
        x_bv = int_list_to_bits({122, 98, 227, 172, 61, 124, 6, 226, 115, 70, 192, 164, 29, 38, 29, 199, 205, 180, 109, 59, 126, 216, 144, 115, 183, 112, 152, 41, 35, 218, 1, 76}, 8);
        r1_bv = int_list_to_bits({74, 64, 1, 8, 53, 76, 6, 98, 51, 4, 64, 164, 29, 32, 29, 134, 4, 176, 64, 43, 114, 8, 144, 115, 182, 112, 0, 1, 2, 194, 0, 76}, 8);
        r2_bv = int_list_to_bits({206, 64, 25, 10, 245, 205, 246, 107, 191, 157, 114, 181, 63, 40, 95, 134, 6, 178, 210, 43, 243, 10, 217, 251, 246, 248, 0, 21, 86, 194, 100, 94}, 8);
    }

    if (swap_r1_r2) {
        // This swaps r1 and r2 which should test if the hashing
        // constraints work properly.
        auto tmp = r2_bv;
        r2_bv = r1_bv;
        r1_bv = tmp;
    }

    // 生成proof
    cout << "Trying to generate proof..." << endl;
    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, h1_bv, h2_bv, x_bv, r1_bv, r2_bv);
    cout << "Proof generated!" << endl;
    cout << "\n======== Proof content =====" << endl;
    cout << proof << endl;
    cout << "============================\n" << endl;

    // 验证proof
    if (!proof) {
        return false;
    } else {
        if (goofy_verification_inputs) {
            // [test] if we generated the proof but try to validate
            // with bogus inputs it shouldn't let us
            return verify_proof(keypair.vk, *proof, h2_bv, h1_bv, x_bv); // 将h1_bv和h2_bv互换位置
        } else {
            // verification should not fail if the proof is generated!
            assert(verify_proof(keypair.vk, *proof, h1_bv, h2_bv, x_bv));
            return true;
        }
    }
}