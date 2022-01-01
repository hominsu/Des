//
// Created by Homin Su on 2021/10/30.
//

#ifndef DES_CRYPT_DES_ENCRYPT_ECB_H_
#define DES_CRYPT_DES_ENCRYPT_ECB_H_

#include "des/des.h"

#include <memory>

namespace crypt {
namespace utils {
/**
 * @brief Calculate the number of bytes to be filled
 * @param _data_size size of data block
 * @return Number of bytes to be filled
 * @retval ::std::size_t
 */
inline ::std::size_t GetMaxPaddingSize(::std::size_t _data_size) {
  ::std::size_t padding_num = des::kBlockSize - _data_size % des::kBlockSize;  // 填充数量，同时也是填充的内容，如果是 8 就填充 8
  if (0 == padding_num) {
    padding_num = des::kBlockSize;
  }
  return padding_num;
}
} // namespace utils

/**
 * @brief 封装了标准 DES 算法和 PKCS7 Padding 数据填充算法, ECB 模式
 * @example
 * @verbatim
 *  crypt::Crypt crypt;
 *  crypt.Init("12345678"); // 初始化密钥
 *
 *  ::std::string in_str("hello!!!");
 *
 *  char cipher_text[1024]{'\0'};
 *  auto encrypt_size = crypt.Encrypt(in_str.c_str(), in_str.size(), cipher_text, true); // 加密
 *
 *  char plain_text[1024]{'\0'};
 *  auto decrypt_size = crypt.Decrypt(cipher_text, encrypt_size, plain_text, true); // 解密
 * @endverbatim
 */
class DesECB {
 private:
  ::std::array<uint64_t, 16> sub_key_{0}; ///< 16 wheels sub-key

 public:
  DesECB();
  ~DesECB();

  /**
 * @brief Initialize the key
 * @param _password 8-byte key
 * @call call ::std::array<uint64_t, 16> Init(const ::std::string &_password) in des/des.cc
 * @callby main.cc
 */
  void Init(const ::std::string &_password);

  /**
   * @brief Encrypt a block of data, encrypt to end will fill data
   * @details 当加密到文件末尾时，使用 PKCS7 数据填充算法对末尾进行填充，例如：缺一个字节就填 1，不缺也要填一个 Block Size
   * @param _in_data Input data
   * @param _in_size Input data size
   * @param _out_data Output data
   * @param _is_end Is end data block?
   * @return Return the size of the encrypted data, possibly greater than the input data(the end data block)
   * @retval ::std::size_t
   * @call inline void Encrypt(const void *_in, void *_out, ::std::array<uint64_t, 16> &_sub_key) in des/des.h
   * @callby main.cc
   */
  ::std::size_t Encrypt(const char *_in_data, ::std::size_t _in_size, char *_out_data, bool _is_end = false);

  /**
   * @brief Decrypt a block of data, decrypt to end will delete the filled data
   * @param _in_data Input data
   * @param _in_size Input data size
   * @param _out_data Output data
   * @param _is_end Is end data block?
   * @return Return the size of the decrypted data, possibly less than the input data(the end data block)
   * @retval ::std::size_t
   * @call inline void Decrypt(const void *_in, void *_out, ::std::array<uint64_t, 16> &_sub_key) in des/des.h
   * @callby main.cc
   */
  ::std::size_t Decrypt(const char *_in_data, ::std::size_t _in_size, char *_out_data, bool _is_end = false);
};
} // namespace crypt

#endif //DES_CRYPT_DES_ENCRYPT_ECB_H_
