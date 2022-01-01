//
// Created by Homin Su on 2021/10/30.
//

#include "des_encrypt_ecb.h"

#include <cstring>
#include <iostream>

#include "des/des.h"

namespace crypt {

DesECB::DesECB() = default;

DesECB::~DesECB() = default;

/**
 * @brief Initialize the key
 * @param _password 8-byte key
 * @call call ::std::array<uint64_t, 16> Init(const ::std::string &_password) in des/des.cc
 * @callby main.cc
 */
void DesECB::Init(const ::std::string &_password) {
  sub_key_ = des::Init(_password);
}

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
::std::size_t DesECB::Encrypt(const char *_in_data, ::std::size_t _in_size, char *_out_data, bool _is_end) {
  if (nullptr == _in_data || nullptr == _out_data || _in_size <= 0) {
    return 0;
  }

  char in_buf[des::kBlockSize]{0};
  char out_buf[des::kBlockSize]{0};

  auto padding_num = static_cast<int>(des::kBlockSize
      - _in_size % des::kBlockSize);  // The size of fills, and also the content of the fill, if it is 8 then fill 8
  auto padding_offset = _in_size % des::kBlockSize; // Filling position

  ::std::size_t write_size = 0;  // Number of bytes after encryption

  ::std::size_t data_size; // Data size per encryption

  for (::std::size_t i = 0; i < _in_size; i += des::kBlockSize) {

    // Handling cases where the number of bytes at the end is less than 8
    if (_in_size - i < des::kBlockSize) {
      data_size = _in_size - i;
    } else {
      data_size = des::kBlockSize;
    }

    // Copy input data to in buffer
    memcpy(in_buf, _in_data + write_size, data_size);

    // PKCS7 Padding
    // 缺多少个字节就填充相对应的大小，如果没缺，也要填充 8 个 8
    if (_is_end && i + des::kBlockSize >= _in_size) {  // Processing the last piece of data
      // ????????88888888
      if (padding_num == des::kBlockSize) {
        // Encrypt the original data
        des::Encrypt(&in_buf, &out_buf, sub_key_);
        memcpy(_out_data + write_size, &out_buf, des::kBlockSize);
        write_size += des::kBlockSize;

        memset(in_buf, padding_num, sizeof(in_buf));  // Filling 8
      } else {
        memset(in_buf + padding_offset, padding_num, padding_num);
      }
    }

    // Encrypt
    des::Encrypt(&in_buf, &out_buf, sub_key_);

    // Copy the encrypted data to _out_data
    memcpy(_out_data + write_size, &out_buf, des::kBlockSize);

    write_size += des::kBlockSize;
  }

  return write_size;
}

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
::std::size_t DesECB::Decrypt(const char *_in_data, ::std::size_t _in_size, char *_out_data, bool _is_end) {
  if (nullptr == _out_data || nullptr == _in_data || _in_size <= 0) {
    return 0;
  }
  ::std::size_t write_size = 0;  /// Number of bytes after decryption

  char in_buf[8]{0};
  char out_buf[8]{0};
  ::std::size_t data_size; // Data size per encryption

  for (::std::size_t i = 0; i < _in_size; i += des::kBlockSize) {
    // Copy input data to in buffer
    memcpy(in_buf, _in_data + write_size, des::kBlockSize);

    // Decrypt
    des::Decrypt(&in_buf, &out_buf, sub_key_);
    data_size = des::kBlockSize;

    // Handling end padding: ??22    ?????55555
    if (_is_end && _in_size - i <= des::kBlockSize) {
      data_size = des::kBlockSize - out_buf[7];

      // ????????88888888
      if (0 == data_size) { break; }
      else if (data_size < 0) {
#ifdef Debug
        ::std::cerr << "Decrypt failed! padding size error" << ::std::endl;
        break;
#elif Release
        throw ::std::runtime_error("Decrypt failed! padding size error");
#endif
      }
    }

    memcpy(_out_data + write_size, &out_buf, data_size);
    write_size += data_size;
  }
  return write_size;
}
} // namespace crypt
