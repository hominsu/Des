//
// Created by Homin Su on 2021/10/28.
//

#include "des.h"

#include <cstring>

// 匿名命名空间, 保存各种 DES 要用到的常量
namespace {
constexpr uint32_t k28_MASK = 0x0fffffff;
constexpr uint64_t k48_MASK = 0x0000ffffffffffff;
constexpr uint64_t k56_MASK = 0x00ffffffffffffff;

constexpr uint64_t kL28_64_MASK = 0x000000000fffffff;
constexpr uint64_t kH28_64_MASK = 0x00fffffff0000000;
constexpr uint64_t kL32_64_MASK = 0x00000000ffffffff;
constexpr uint64_t kH32_64_MASK = 0xffffffff00000000;

///< Initial Permutation
constexpr unsigned char kIP[] = {57, 49, 41, 33, 25, 17, 9, 1,
                                 59, 51, 43, 35, 27, 19, 11, 3,
                                 61, 53, 45, 37, 29, 21, 13, 5,
                                 63, 55, 47, 39, 31, 23, 15, 7,
                                 56, 48, 40, 32, 24, 16, 8, 0,
                                 58, 50, 42, 34, 26, 18, 10, 2,
                                 60, 52, 44, 36, 28, 20, 12, 4,
                                 62, 54, 46, 38, 30, 22, 14, 6};

///< Inverse Initial Permutation
constexpr unsigned char kIP_1[] = {39, 7, 47, 15, 55, 23, 63, 31,
                                   38, 6, 46, 14, 54, 22, 62, 30,
                                   37, 5, 45, 13, 53, 21, 61, 29,
                                   36, 4, 44, 12, 52, 20, 60, 28,
                                   35, 3, 43, 11, 51, 19, 59, 27,
                                   34, 2, 42, 10, 50, 18, 58, 26,
                                   33, 1, 41, 9, 49, 17, 57, 25,
                                   32, 0, 40, 8, 48, 16, 56, 24};

///< Permuted Choice 1, the 64-bit key is compressed to 56 bits
constexpr unsigned char kPC_1[] = {56, 48, 40, 32, 24, 16, 8,
                                   0, 57, 49, 41, 33, 25, 17,
                                   9, 1, 58, 50, 42, 34, 26,
                                   18, 10, 2, 59, 51, 43, 35,
                                   62, 54, 46, 38, 30, 22, 14,
                                   6, 61, 53, 45, 37, 29, 21,
                                   13, 5, 60, 52, 44, 36, 28,
                                   20, 12, 4, 27, 19, 11, 3};

///< Permuted Choice 2, the 56-bit key is compressed to 48 bits
constexpr unsigned char kPC_2[] = {13, 16, 10, 23, 0, 4,
                                   2, 27, 14, 5, 20, 9,
                                   22, 18, 11, 3, 25, 7,
                                   15, 6, 26, 19, 12, 1,
                                   40, 51, 30, 36, 46, 54,
                                   29, 39, 50, 44, 32, 47,
                                   43, 48, 38, 55, 33, 52,
                                   45, 41, 49, 35, 28, 31};

///< Number of left circular shift
constexpr unsigned char kShiftBits[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// 轮函数相关设定

///< Extended Permutation，32-bit data extended to 48 bits
constexpr unsigned char kE[] = {31, 0, 1, 2, 3, 4,
                                3, 4, 5, 6, 7, 8,
                                7, 8, 9, 10, 11, 12,
                                11, 12, 13, 14, 15, 16,
                                15, 16, 17, 18, 19, 20,
                                19, 20, 21, 22, 23, 24,
                                23, 24, 25, 26, 27, 28,
                                27, 28, 29, 30, 31, 0};

///< Substitution Boxes, eight S-boxes which map 6 to 4 bits
constexpr unsigned char kSBox[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

///< 32-bit Perm P
constexpr unsigned char kP[] = {15, 6, 19, 20,
                                28, 11, 27, 16,
                                0, 14, 22, 25,
                                4, 17, 30, 9,
                                1, 7, 23, 13,
                                31, 26, 2, 8,
                                18, 12, 29, 5,
                                21, 10, 3, 24};

uint64_t r_expend_e = 0;    ///< Save the data for the E/P table extension
uint32_t r_tmp_32 = 0;      ///< Save the data for S-boxes output
uint32_t r_output_32 = 0;   ///< Round function output

uint64_t c_tmp_64 = 0;      ///< Temp value for Crypt function
uint32_t c_left_32 = 0;     ///< Left 32 bits for Crypt function
uint32_t c_right_32 = 0;    ///< Right 32 bits for Crypt function
uint64_t c_text_64 = 0;     ///< Save the plain/cipher text in Crypt function

} // namespace

namespace des {

/**
 * @brief Convert 8 bytes to uint64_t(64 bits)
 * @param c Char array ptr
 * @return 64 bits data
 * @retval uint64_t
 */
inline uint64_t CharToBits(const char c[8]) {
  uint64_t byte;
  memcpy(&byte, c, 8);
  return byte;
}

/**
 * @brief Left circular shift a 28 bits sub key
 * @param _k sub key
 * @param _shift_num shift digital
 * @return Left shifted sub key
 * @retval uint32_t
 */
inline uint32_t KeyLeftShift(uint32_t &_k, const unsigned char &_shift_num) {
  // k28_MASK is 0x0fffffff, it overwrites any other data larger than 28 bits
  return (_k << _shift_num | _k >> (28 - _shift_num)) & k28_MASK;
}

/**
 * @brief Initial Key, Generate 16 48-bit sub-key
 * @details Initialize key, the key length is 8 bytes, excess is discarded and insufficient is 0
 * @param _password 8 bytes key
 * @return 16 wheels sub-keys
 * @retval ::std::array<uint64_t, 16>
 */
::std::array<uint64_t, 16> Init(const ::std::string &_password) {
  char k[8]{0};

  // excess is discarded and insufficient is 0
  memcpy(k, _password.c_str(), 8); // copy the keys into the char array, only copy 8 bytes, excess is discarded and insufficient is 0

  uint64_t key = CharToBits(k);

  uint64_t key_56 = 0;

  // permuted choice 1, the 64-bit key is compressed to 56 bits
  for (unsigned char value: kPC_1) {
    key_56 <<= 1;
    key_56 |= key >> value & 0x1;
  }

  uint32_t left_key;
  uint32_t right_key;

  // the 56-bit key is divided into two 28-bit keys
  left_key = key_56 >> 28;
  right_key = key_56 & kL28_64_MASK;

  uint64_t key_48 = 0;
  ::std::array<uint64_t, 16> sub_keys{0};  // sub-keys for 16 rounds of encryption and decryption

  // 16 rounds
  for (unsigned char i = 0; i < 16; ++i) {

    // left circular shift
    left_key = KeyLeftShift(left_key, kShiftBits[i]);
    right_key = KeyLeftShift(right_key, kShiftBits[i]);

    // 拼接
    key_56 = left_key;
    key_56 = key_56 << 28 | right_key;

    // permuted choice 2, the 56-bit key is compressed to 48 bits
    for (unsigned char value: kPC_2) {
      key_48 <<= 1;
      key_48 |= key_56 >> value & 0x1;
    }

    sub_keys[i] = key_48;
  }

  return sub_keys;
}

/**
 * @brief round function
 * @param _r Previous round function right 32 bits
 * @param _k 48 位子密钥
 * @return Encrypted 32-bit data
 * @retval uint32_t
 */
uint32_t RoundFunc(const uint32_t &_r, const uint64_t &_k) {
  // extended permutation，32-bit data extended to 48 bits
  for (unsigned char value: kE) {
    r_expend_e <<= 1;
    r_expend_e |= _r >> value & 0x1;
  }

  // the extended plaintext is heterogeneous with the key
  r_expend_e = r_expend_e ^ _k;

  r_tmp_32 = 0;  // temporarily store the output of the Substitution Boxes

  // S Box
  for (unsigned char i = 0; i < 8; ++i) {
    // compression replacement the data
    uint8_t value = kSBox[i][ExpendBin2Dec(r_expend_e, i + 1, i + 0)][ExpendBin2Dec(r_expend_e,
                                                                                    i + 5,
                                                                                    i + 4,
                                                                                    i + 3,
                                                                                    i + 2)];
    r_tmp_32 <<= 4;
    r_tmp_32 |= value & 0xf;
  }

  r_output_32 = 0;

  // 32-bit Perm P
  for (unsigned char value: kP) {
    r_output_32 <<= 1;
    r_output_32 |= r_tmp_32 >> value & 0x1;
  }

  return r_output_32;
}

/**
 * @brief Encryption and decryption, single encryption and decryption of 8 bytes
 * @param _in Input Data
 * @param _out Output Data
 * @param _sub_key Sixteen Wheels sub-key
 * @param _is_encrypt Encryption/Decryption
 */
void Crypt(const void *_in, void *_out, ::std::array<uint64_t, 16> &_sub_key, bool _is_encrypt) {
  char src[8]{0};
  memcpy(static_cast<void *>(src), _in, 8);

  c_text_64 = CharToBits(src);

  c_tmp_64 = 0;

  // Initial Permutation
  for (unsigned char value: kIP) {
    c_tmp_64 <<= 1;
    c_tmp_64 |= c_text_64 >> value & 0x1;
  }

  // Divided into a left half and a right half
  c_left_32 = c_tmp_64 >> 32;
  c_right_32 = c_tmp_64 & kL32_64_MASK;

  // 16 round functions
  if (_is_encrypt) {
    // Encryption
    for (auto &sub_key: _sub_key) {
      uint32_t tmp = c_right_32;
      c_right_32 = c_left_32 ^ RoundFunc(c_right_32, sub_key);
      c_left_32 = tmp;
    }
  } else {
    // Decryption, key reversal
    for (unsigned char index = 0; index < 16; ++index) {
      uint32_t tmp = c_right_32;
      c_right_32 = c_left_32 ^ RoundFunc(c_right_32, _sub_key[15 - index]);
      c_left_32 = tmp;
    }
  }

  // Swap the left and right halves, and merge
  c_tmp_64 = c_right_32;
  c_tmp_64 = c_tmp_64 << 32 | c_left_32;

  // Inverse Initial Permutation
  for (unsigned char value: kIP_1) {
    c_text_64 <<= 1;
    c_text_64 |= c_tmp_64 >> value & 0x1;
  }

  memcpy(_out, &c_text_64, 8);
}
} // namespace des
