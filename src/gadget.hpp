#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"

#include <iostream> //--Agzs

const size_t sha256_digest_len = 256;

/*
// sha256算法流程：https://blog.csdn.net/code_segment/article/details/80273482
computed by:

        unsigned long long bitlen = 256;

        unsigned char padding[32] = {0x80, 0x00, 0x00, 0x00, // 24 bytes of padding(192位的bit填充，填充的最高位是1，sha256算法要求)
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     bitlen >> 56, bitlen >> 48, bitlen >> 40, bitlen >> 32, // message length（64-bit 表示的初始报文（填充前）的位长度）
                                     bitlen >> 24, bitlen >> 16, bitlen >> 8, bitlen
                                    };

        std::vector<bool> padding_bv(256);

        convertBytesToVector(padding, padding_bv);

        printVector(padding_bv);
*/
bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

template<typename FieldT>
class l_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
    std::shared_ptr<digest_variable<FieldT>> h2_var; /* H(R2) */

    std::shared_ptr<digest_variable<FieldT>> x_var; /* X */
    std::shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */
    std::shared_ptr<digest_variable<FieldT>> r2_var; /* R2 */

    std::shared_ptr<block_variable<FieldT>> h_r1_block; /* 512 bit block that contains r1 + padding 分组处理，填充比特*/
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1; /* hashing gadget for r1 */

    std::shared_ptr<block_variable<FieldT>> h_r2_block; /* 512 bit block that contains r2 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r2; /* hashing gadget for r2 */

    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding 填充*/

    //类l_gadget的构造函数
    l_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "l_gadget")
    {
        // Allocate space for the verifier input (H1, H2, X).
        const size_t input_size_in_bits = sha256_digest_len * 3;
        {
            // We use a "multipacking" technique which allows us to constrain
            // the input bits in as few field elements as possible.
            
            // printf("\n======== test content =====\n");
            // printf("FieldT::capacity() = %zu", FieldT::capacity());
            // printf("\n============================\n");
            // FieldT::capacity() is 253.
            // input_size_in_field_elements = (256*3 + 253-1) / 253 = 4
            const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
            input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
            this->pb.set_input_sizes(input_size_in_field_elements);
        }

        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero")); // zero 由0变为有限域上5 in finite field
        // printf("\n======== test content =====\n");
        // printf("zero = %zu\n", zero);
        // printf("\nONE = %zu", ONE);
        // printf("\n============================\n");

        // SHA256's length padding 位数填充至512bit, 转换为域上相应的值
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE); // 类似于push_back()，但是比其速度更快, ONE是有限域上的0
            else
                padding_var.emplace_back(zero); // zero是有限域上的5
        }

        // Verifier (and prover) inputs:
        h1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h1"));// reset重置一个新的shared_ptr对象"h1"
        h2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h2"));
        x_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "x"));

        // 在指定位置input_as_bits.end()前“插入”区间 [ *_var->bits.begin(), *_var->bits.end() ) 的所有元素.
        input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h2_var->bits.begin(), h2_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), x_var->bits.begin(), x_var->bits.end());
        
        // Multipacking 分块处理，块大小由FieldT::capacity()确定
        assert(input_as_bits.size() == input_size_in_bits); // 插入的h1, h2, x, 每个长度都为sha256_digest_len
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));


        // Prover inputs:
        r1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r1"));
        r2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r2"));

        // IV for SHA256 初始化SHA256缓存
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        // Initialize the block gadget for r1's hash
        h_r1_block.reset(new block_variable<FieldT>(pb, {
            r1_var->bits,
            padding_var
        }, "h_r1_block"));

        // Initialize the hash gadget for r1's hash
        h_r1.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r1_block->bits,
                                                                  *h1_var,
                                                                  "h_r1"));

        // Initialize the block gadget for r2's hash
        h_r2_block.reset(new block_variable<FieldT>(pb, {
            r2_var->bits,
            padding_var
        }, "h_r2_block"));

        // Initialize the hash gadget for r2's hash
        h_r2.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r2_block->bits,
                                                                  *h2_var,
                                                                  "h_r2"));
    }

    //类l_gadget生成约束
    void generate_r1cs_constraints()
    {   
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r1_var->generate_r1cs_constraints();
        r2_var->generate_r1cs_constraints();

        // adding constraint 1 * zero = FieldT::zero() --Agzs*/
        // printf("\n======== field content =====\n");
        // printf("zero = %zu\n", FieldT::zero());
        // printf("\none = %zu", FieldT::one());
        // printf("\n============================\n"); 
        // FieldT::zero() is 0, while FieldT::one() is big number such as 140736227926016
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

        // printf("\n============== after generating r1cs constraints ===\n");
        // unsigned int index = 3;
        // printf("r2_var->bits[%d] = %zu\n", index, r2_var->bits[index]);
        // printf("x_var->bits[%d] =  %zu\n", index, x_var->bits[index]);
        // printf("r1_var->bits[%d] * (-1) =  %d\n", index, r1_var->bits[index] * (-1));
        // printf("b + c - a =  %zu\n", r2_var->bits[index] +  x_var->bits[index] + r1_var->bits[index] * (-1));
        // printf("========================================\n\n");

        // r2_var->bits: 1030, 1031, 1032, ....
        // x_var->bits: 518, 519, 520, ...
        // r1_var->bits: 774, 775, 776, ...

        for (unsigned int i = 0; i < sha256_digest_len; i++) {
            // This is the constraint that R1 = R2 ^ X.
            // (2*b)*c = b+c - a  利用真值表确定

            //cout << "r2_var->bits[i] * 2" << r2_var->bits[i] * 2 << endl;
            //cout << "x_var->bits[i]" << x_var->bits[i] << endl;
            //cout << "r1_var->bits[i] * (-1)" << r1_var->bits[i] * (-1) << endl;
            //cout << proof << endl;
            
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { r2_var->bits[i] * 2 }, // 2*b
                    { x_var->bits[i] }, // c
                    { r2_var->bits[i], x_var->bits[i], r1_var->bits[i] * (-1) }), // b+c - a
                FMT(this->annotation_prefix, " xor_%zu", i));
        }

        // These are the constraints to ensure the hashes validate.
        h_r1->generate_r1cs_constraints();
        h_r2->generate_r1cs_constraints();
    }

    //类l_gadget生成witness
    void generate_r1cs_witness(const bit_vector &h1,
                               const bit_vector &h2,
                               const bit_vector &x,
                               const bit_vector &r1,
                               const bit_vector &r2
                              )
    {
        // Fill our digests with our witnessed data, 0,1 => zero,one
        x_var->bits.fill_with_bits(this->pb, x);
        r1_var->bits.fill_with_bits(this->pb, r1);
        r2_var->bits.fill_with_bits(this->pb, r2);

        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our other gadgets
        h_r1->generate_r1cs_witness();
        h_r2->generate_r1cs_witness();
        unpack_inputs->generate_r1cs_witness_from_bits();

        h1_var->bits.fill_with_bits(this->pb, h1);
        h2_var->bits.fill_with_bits(this->pb, h2);
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &h1,
                                             const bit_vector &h2,
                                             const bit_vector &x
                                            )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    assert(h1.size() == sha256_digest_len);
    assert(h2.size() == sha256_digest_len);
    assert(x.size() == sha256_digest_len);

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());
    input_as_bits.insert(input_as_bits.end(), h2.begin(), h2.end());
    input_as_bits.insert(input_as_bits.end(), x.begin(), x.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}
