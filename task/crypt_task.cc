//
// Created by Homin Su on 2021/11/3.
//

#include "crypt_task.h"

#ifdef Debug
#include <iostream>
#endif

#include "../data/data.h"
#include "../crypt/crypt.h"

/**
 * @brief 初始化加密任务
 * @param _password 密码
 */
void CryptTask::Init(const std::string &_password) {
  crypt_ = std::make_shared<crypt::Crypt>();
  crypt_->Init(_password);
}

/**
 * @brief 线程主函数
 */
void CryptTask::Main() {
#ifdef Debug
  std::cout << "XCryptTask::Main() Start" << std::endl;
#endif
  while (is_running) {
    auto data = PopFront();
    if (nullptr == data) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      continue;
    }
    auto out = Data::Make(memory_resource_);
    size_t out_size = data->size() + crypt::utils::GetMaxPaddingSize(data->size());
    out->New(out_size);

    size_t crypt_data_size;
    if (is_encrypt_) {
      crypt_data_size =
          crypt_->Encrypt(static_cast<char *>(data->data()),
                          data->size(),
                          static_cast<char *>(out->data()),
                          data->end());
    } else {
      crypt_data_size =
          crypt_->Decrypt(static_cast<char *>(data->data()),
                          data->size(),
                          static_cast<char *>(out->data()),
                          data->end());
    }

    out->set_size(crypt_data_size);
    out->set_end(data->end());  // 设置状态

#ifdef Debug
    std::cout << "<" << out->size() << ">" << std::flush;
#endif

    // 如果有下一个责任链，就 push 数据进去
    if (nullptr != next_) {
      next_->PushBack(out);
    }

    // 到结尾了就退出
    if (data->end()) {
      break;
    }
  }
#ifdef Debug
  std::cout << std::endl << "XCryptTask::Main() End" << std::endl;;
#endif

  set_return(0);
}

/**
 * @brief 设置加密或解密
 * @param _is_encrypt 加密或解密
 */
void CryptTask::set_is_encrypt(bool _is_encrypt) {
  is_encrypt_ = _is_encrypt;
}
