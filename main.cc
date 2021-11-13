//
// Created by Homin Su on 2021/10/28.
//

#include <iostream>
#include <list>
#include <chrono>
#include <filesystem>

#include "task/file_crypt.h"

enum class Unit {
  Byte, KB, MB, GB
};

template<typename Ts>
double convert(Ts _size, Unit _unit) {
  auto result = static_cast<double>(_size);

  switch (_unit) {
    case Unit::GB: result /= 1024;
    case Unit::MB: result /= 1024;
    case Unit::KB: result /= 1024;
    case Unit::Byte: result /= 1;
    default:break;
  }

  return result;
}

int main(int _argc, char *_argv[]) {
  if (_argc != 5) {
    std::cerr << "param error!" << std::endl;
    std::cout << "\tEncrypt folder: " << _argv[0] << " -e src_dir dst_dir password" << std::endl;
    std::cout << "\tDecrypt folder: " << _argv[0] << " -d src_dir dst_dir password" << std::endl;
    exit(EXIT_FAILURE);
  }

  std::string option = _argv[1];    // 加解密选项
  std::string src_dir = _argv[2];   // 输入文件夹
  std::string dst_dir = _argv[3];   // 输入文件夹
  std::string password = _argv[4];  // 密钥

  bool is_encrypt;
  if ("-e" == option) {
    is_encrypt = true;
  } else if ("-d" == option) {
    is_encrypt = false;
  }

  // 源文件目录是否存在
  if (!std::filesystem::exists(src_dir)) {
    std::cerr << "src_dir not exist" << std::endl;
    return EXIT_FAILURE;
  }

  // 创建输出文件夹
  if (!std::filesystem::exists(dst_dir)) {
    std::filesystem::create_directories(dst_dir);
  }

  if (dst_dir[dst_dir.size() - 1] != '/') {
    dst_dir += '/';
  }

  // 线程安全的内存资源
  auto memory_resource = std::make_shared<std::pmr::synchronized_pool_resource>();

  // 文件列表
  auto file_crypt_list = std::list<std::shared_ptr<FileCrypt>>();

  size_t read_bytes = 0;
  size_t crypt_bytes = 0;
  size_t write_bytes = 0;

  // 任务开始执行时间
  auto start_time_point = std::chrono::system_clock::now();

  // 遍历输入目录
  for (auto &it: std::filesystem::directory_iterator(src_dir)) {
    // 只处理文件
    if (!it.is_regular_file()) {
      continue;
    }

    auto file_crypt = std::make_shared<FileCrypt>();

    auto ok = file_crypt->Start(it.path().string(),
                                dst_dir + it.path().filename().string(),
                                password,
                                is_encrypt,
                                memory_resource);
    if (ok) {
      file_crypt_list.push_back(file_crypt);
    }
  }

  // 等待任务执行完成
  size_t task_num = 0;
  for (auto &file_crypt: file_crypt_list) {
    file_crypt->Wait();
    read_bytes += file_crypt->read_bytes_;
    crypt_bytes += file_crypt->crypt_bytes_;
    write_bytes += file_crypt->write_bytes_;
    std::cout << ++task_num << ": in: [" << file_crypt->in_file_ << "], out: [" << file_crypt->out_file_ << "]"
              << std::endl;
  }

  auto usage_times = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now() - start_time_point).count();

  printf("\nUsage time: %lld ms\n", usage_times);
  printf("\tRead bytes:  %lf MB\n", convert(read_bytes, Unit::MB));
  printf("\tCrypt bytes: %lf MB\n", convert(crypt_bytes, Unit::MB));
  printf("\tWrite bytes: %lf MB\n", convert(write_bytes, Unit::MB));

  auto megabytes_per_second = static_cast<double>(read_bytes) / (static_cast<double>(usage_times) / 1000);

  printf("\nSpeed: %lf MB/s, %lf mbps/s\n",
         convert(megabytes_per_second, Unit::MB),
         convert(megabytes_per_second, Unit::MB) * 8);

  return 0;
}

// 加密: build/Des -e test/src test/enc 123456
// 解密: build/Des -d test/enc test/dec 123456
