//
// Created by Homin Su on 2021/11/3.
//

#ifndef DES_TASK_WRITE_TASK_H_
#define DES_TASK_WRITE_TASK_H_

#include <string>
#include <fstream>

#include "task_base.h"

/**
 * @brief 写出任务
 */
class WriteTask : public TaskBase {
 private:
  std::ofstream ofs_;
  std::string file_name_; ///< 文件路径

 public:
  /**
   * @brief 初始化写出任务
   * @param _file_name 文件名
   * @return 初始化状态
   */
  bool Init(const std::string &_file_name);

 private:
  /**
   * @brief 线程主函数
   */
  void Main() override;

  /**
   * @brief 打开文件
   * @return 是否打开
   */
  bool OpenFile();
};

#endif //DES_TASK_WRITE_TASK_H_
