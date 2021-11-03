//
// Created by Homin Su on 2021/11/3.
//

#ifndef DES_TASK_READ_TASK_H_
#define DES_TASK_READ_TASK_H_

#include <string>
#include <fstream>

#include "task_base.h"

/**
 * @brief 读取任务
 */
class ReadTask : public TaskBase {
 private:
  std::ifstream ifs_;     ///< 读取文件流
  std::string file_name_; ///< 文件路径

 public:
  /**
   * @brief 初始化读取任务，获取文件大小
   * @param _file_name 文件名
   * @return 是否初始化成功
   */
  bool Init(const std::string &_file_name);

 private:
  /**
   * 线程入口函数
   */
  void Main() override;

  /**
   * @brief 打开文件
   * @return 是否打开
   */
  bool OpenFile();
};

#endif //DES_TASK_READ_TASK_H_
