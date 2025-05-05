// File: /data/jenkins/jenkins_hk4e/workspace/hk4e_3.4_dev/framework/common/minet/net_tools/src/proto_utils.cpp

// Line 86: range 000000000C7FF0F6-000000000C7FF276
int32_t ProtoUtils::init() {
  // 如果已经初始化过，直接返回
  if (ProtoUtils::is_init_) {
      common::milog::MiLogStream log_stream;
      log_stream.init(&common::milog::MiLogDefault::default_log_obj_, 3u, "src/proto_utils.cpp", "init", 90);
      log_stream << "class is inited before, skip this call";
      log_stream.~MiLogStream();
      return 0;
  }

  // 初始化 retcode 映射表
  if (ProtoUtils::initRetcodeMap()) {
      return -1;
  }

  // 初始化 cmd_id 配置映射表
  if (ProtoUtils::initCmdIdConfigMap()) {
      return -1;
  }

  // 初始化命令数据
  int32_t inited = ProtoUtils::initCmdData();
  if (inited) {
      return -1;
  }

  // 调用 protobuf 的 generated_factory 方法
  google::protobuf::MessageFactory::generated_factory(nullptr);

  // 标记为已初始化
  ProtoUtils::is_init_ = true;

  // 如果需要显示初始化日志，打印日志
  if (ProtoUtils::is_show_init_log_) {
      common::milog::MiLogStream log_stream;
      log_stream.init(&common::milog::MiLogDefault::default_log_obj_, 2u, "src/proto_utils.cpp", "init", 114);
      log_stream << "init succ with cmd_num=" 
                << ProtoUtils::cmd_to_name_map_.size() 
                << ", retcode_num=" 
                << ProtoUtils::retcode_to_name_map_.size();
      log_stream.~MiLogStream();
  }

  return inited;
}

struct CmdIdConfig
{
    uint32_t begin_cmd_id;
    uint32_t end_cmd_id;
};

enum CmdIdConfigType
{
    CMD_ID_CONFIG_INVALID = 0,
    CMD_ID_CONFIG_BEGIN   = 1,
    CMD_ID_CONFIG_END     = 2
};

static std::map<std::string, CmdIdConfig> cmd_id_config_map_;

// Line 122: range 000000000C7FDB40-000000000C7FEA72
/*
该函数用于初始化命令 ID 与 proto 文件之间的映射关系（cmd_id_config_map_），以便后续能够通过命令 ID 快速查找对应的 proto 文件和消息定义。

首先获取 protobuf 的枚举描述符。
然后遍历每个枚举值，解析其命名格式（是否以 _BEGIN 或 _END 结尾）。
将有效的枚举信息插入到 cmd_id_config_map_ 中。
最后检查是否有冲突的 cmd_id 范围，并记录日志。
 */
int32_t ProtoUtils::initCmdIdConfigMap()
{
    const google::protobuf::DescriptorPool* pool = google::protobuf::DescriptorPool::generated_pool();
    if (!pool)
    {
        LOG_ERROR << "Failed to get generated DescriptorPool";
        return -1;
    }

    const google::protobuf::EnumDescriptor* enumDesc = pool->FindEnumTypeByName(ProtoConst::cmd_id_config);
    if (!enumDesc)
    {
        LOG_ERROR << "Can't find enum: " << ProtoConst::cmd_id_config;
        return -1;
    }

    uint32_t valueCount = enumDesc->value_count();
    std::string lastFileName;
    std::string lastName;
    uint32_t lastValue = 0;

    std::map<std::string, CmdIdConfig> tmpMap; // 临时存储结构

    for (uint32_t i = 0; i < valueCount; ++i)
    {
        const google::protobuf::EnumValueDescriptor* valueDesc = enumDesc->value(i);
        if (!valueDesc)
        {
            LOG_ERROR << "Invalid enum value at index: " << i;
            return -1;
        }

        std::string fullName = valueDesc->name();
        std::string fileKeyName;
        CmdIdConfigType type;

        if (splitCmdIdConfigName(&fullName, &fileKeyName, &type))
        {
            LOG_ERROR << "Invalid enum name: " << fullName;
            return -1;
        }

        uint32_t cmdId = valueDesc->number();

        if (type == CMD_ID_CONFIG_BEGIN)
        {
            if (!lastName.empty())
            {
                LOG_ERROR << "Miss END for: " << lastName << "=" << lastValue;
                return -1;
            }

            lastFileName = fileKeyName;
            lastName = fullName;
            lastValue = cmdId;
        }
        else if (type == CMD_ID_CONFIG_END)
        {
            if (lastFileName != fileKeyName || cmdId <= lastValue)
            {
                LOG_ERROR << "Begin/End config error for: " << fullName << "=" << cmdId;
                return -1;
            }

            CmdIdConfig config;
            config.begin_cmd_id = lastValue;
            config.end_cmd_id = cmdId;

            auto it = tmpMap.find(fileKeyName);
            if (it != tmpMap.end())
            {
                LOG_ERROR << "Conflict cmd_id config: " << it->second.begin_cmd_id << "->" << it->second.end_cmd_id
                          << " and " << lastValue << "->" << cmdId;
                return -1;
            }

            tmpMap[fileKeyName] = config;

            if (is_show_init_log_)
            {
                LOG_INFO << "Add cmd_id config: " << lastValue << "->" << cmdId << " for " << fileKeyName << ".proto";
            }

            lastFileName.clear();
            lastName.clear();
            lastValue = 0;
        }
        else
        {
            LOG_ERROR << "Invalid enum type: " << static_cast<uint32_t>(type);
            return -1;
        }
    }

    if (!lastFileName.empty())
    {
        LOG_ERROR << "Miss END for: " << lastName << "=" << lastValue;
        return -1;
    }

    // 插入最终 map
    for (const auto& pair : tmpMap)
    {
        cmd_id_config_map_[pair.first] = pair.second;
    }

    return 0;
}

// Line 244: range 000000000C7FEA78-000000000C7FF0F0
int32_t ProtoUtils::initRetcodeMap() {
  // 获取生成的 protobuf DescriptorPool
  const google::protobuf::DescriptorPool* descriptor_pool = google::protobuf::DescriptorPool::generated_pool();
  if (!descriptor_pool) {
      common::milog::MiLogStream log_stream;
      log_stream.init(&common::milog::MiLogDefault::default_log_obj_, 4u, "src/proto_utils.cpp", "initRetcodeMap", 249);
      log_stream << "generated_pool failed";
      log_stream.~MiLogStream();
      return -1;
  }

  // 查找 retcode 枚举类型
  const google::protobuf::EnumDescriptor* enum_descriptor = descriptor_pool->FindEnumTypeByName(ProtoConst::retcode);
  if (!enum_descriptor) {
      common::milog::MiLogStream log_stream;
      log_stream.init(&common::milog::MiLogDefault::default_log_obj_, 4u, "src/proto_utils.cpp", "initRetcodeMap", 249);
      log_stream << "can not find enum " << ProtoConst::retcode << " in proto file";
      log_stream.~MiLogStream();
      return -1;
  }

  // 遍历枚举值并初始化映射表
  uint32_t value_count = enum_descriptor->value_count();
  for (uint32_t i = 0; i < value_count; ++i) {
      const google::protobuf::EnumValueDescriptor* enum_value = enum_descriptor->value(i);
      if (!enum_value) {
          common::milog::MiLogStream log_stream;
          log_stream.init(&common::milog::MiLogDefault::default_log_obj_, 4u, "src/proto_utils.cpp", "initRetcodeMap", 260);
          log_stream << "invalid enum value at index " << i;
          log_stream.~MiLogStream();
          return -1;
      }

      int retcode = enum_value->number();
      std::string name = enum_value->name();

      // 插入到 retcode_to_name_map_ 中
      auto it = ProtoUtils::retcode_to_name_map_.find(retcode);
      if (it == ProtoUtils::retcode_to_name_map_.end()) {
          ProtoUtils::retcode_to_name_map_[retcode] = name;
      } else {
          common::milog::MiLogStream log_stream;
          log_stream.init(&common::milog::MiLogDefault::default_log_obj_, 4u, "src/proto_utils.cpp", "initRetcodeMap", 270);
          log_stream << "find repeat retcode=" << retcode << " in msg '" << name << "'";
          log_stream.~MiLogStream();
          return -1;
      }

      // 插入到 retcode_to_value_map_ 中
      auto it2 = ProtoUtils::retcode_to_value_map_.find(name);
      if (it2 == ProtoUtils::retcode_to_value_map_.end()) {
          ProtoUtils::retcode_to_value_map_[name] = retcode;
      } else {
          common::milog::MiLogStream log_stream;
          log_stream.init(&common::milog::MiLogDefault::default_log_obj_, 4u, "src/proto_utils.cpp", "initRetcodeMap", 280);
          log_stream << "find repeat name=" << name << " with retcode=" << retcode;
          log_stream.~MiLogStream();
          return -1;
      }
  }

  // 如果需要显示初始化日志，打印日志
  if (ProtoUtils::is_show_init_log_) {
      common::milog::MiLogStream log_stream;
      log_stream.init(&common::milog::MiLogDefault::default_log_obj_, 1u, "src/proto_utils.cpp", "initRetcodeMap", 269);
      log_stream << "load " << value_count << " Retcode values from proto file";
      log_stream.~MiLogStream();
  }

  return 0;
}

// Line 276: range 000000000C7FC1EA-000000000C7FC245
int32_t ProtoUtils::initCmdData() {
  // 定义一个 lambda 函数，用于处理每个 proto 文件
  std::function<int(const std::string&)> callback = [](const std::string& file_name) -> int {
      // 实际逻辑由开发者补充
      return 0; // 假设默认返回 0 表示成功
  };

  // 调用 foreachProtoFile 遍历所有 proto 文件并应用回调函数
  int32_t result = ProtoUtils::foreachProtoFile(callback);

  // 如果回调函数有管理器（manager），调用其管理器释放资源
  if (callback._M_manager) {
      callback._M_manager((std::_Any_data*)&callback, (const std::_Any_data*)&callback, __destroy_functor);
  }

  return result;
}

// Line 292: range 000000000C7FC060-000000000C7FC1E5
__int64 __fastcall ProtoUtils::foreachProtoFile(google::protobuf::DescriptorPool *a1)
{
  std::_Rb_tree_node_base *v1; // r13
  __int64 v2; // rax
  __int64 v3; // rbp
  __int64 i; // rax
  const std::string *v6; // rbx
  common::milog::MiLogStream v7[2]; // [rsp+0h] [rbp-48h] BYREF

  v2 = google::protobuf::DescriptorPool::generated_pool(a1);
  if ( !v2 )
  {
    common::milog::MiLogStream::MiLogStream(
      v7,
      &common::milog::MiLogDefault::default_log_obj_,
      4u,
      "src/proto_utils.cpp",
      "foreachProtoFile",
      297);
    common::milog::MiLogStream::operator()(v7, "generated_pool failed");
    common::milog::MiLogStream::~MiLogStream(v7);
    return 0xFFFFFFFFLL;
  }
  if ( *(_BYTE *)(((unsigned __int64)(v2 + 8) >> 3) + 0x7FFF8000) )
  {
    __asan_report_load8(v2 + 8);
    goto LABEL_8;
  }
  v3 = *(_QWORD *)(v2 + 8);
  if ( !v3 )
  {
LABEL_8:
    common::milog::MiLogStream::MiLogStream(
      v7,
      &common::milog::MiLogDefault::default_log_obj_,
      4u,
      "src/proto_utils.cpp",
      "foreachProtoFile",
      306);
    common::milog::MiLogStream::operator()(v7, "fallback_database_ is nullptr");
    common::milog::MiLogStream::~MiLogStream(v7);
    return 0xFFFFFFFFLL;
  }
  if ( *(_BYTE *)(((unsigned __int64)(v3 + 32) >> 3) + 0x7FFF8000) )
  {
    __asan_report_load8(v3 + 32);
    goto LABEL_10;
  }
  for ( i = *(_QWORD *)(v3 + 32); ; i = std::_Rb_tree_increment(v1) )
  {
    v1 = (std::_Rb_tree_node_base *)i;
    if ( i == v3 + 16 )
      break;
    v6 = (const std::string *)(i + 32);
    if ( std::string::find(i + 32, "google/", 0LL)
      && std::function<int ()(std::string const&)>::operator()(
           (const std::function<int(const std::string&)> *const)a1,
           v6) )
    {
      return 0xFFFFFFFFLL;
    }
LABEL_10:
    ;
  }
  return 0LL;
};

static std::map<std::string, CmdIdConfig> cmd_id_config_map_;
static std::map<uint32_t, std::string> cmd_to_name_map_;
static std::map<std::string, uint32_t> name_to_cmd_map_;
static std::map<uint32_t, uint32_t> cmd_to_channel_map_;
static std::map<uint32_t, const google::protobuf::Descriptor*> cmd_to_desc_map_;
static std::map<uint32_t, ProtoCmdType> cmd_to_type_map_;

static std::set<uint32_t> allow_client_cmd_set_;
static std::set<uint32_t> reliable_cmd_set_;

// Line 345: range 000000000C7FF27C-000000000C80014E
int32_t ProtoUtils::addCmdProtoFile(const std::string* file_name) {
  // 初始化局部变量
  int32_t result = 0;
  uint32_t cmd_msg_count = 0;
  const google::protobuf::DescriptorPool* pool = google::protobuf::DescriptorPool::generated_pool();
  
  // 查找指定文件名的 proto 文件描述符
  const google::protobuf::FileDescriptor* file_desc = pool->FindFileByName(*file_name);
  if (!file_desc) {
      LOG_ERROR << "file ptr is null";
      return -1;
  }

  // 获取该文件中定义的消息数量
  uint32_t msg_count = file_desc->message_type_count();
  if (msg_count == 0) {
      return 0;
  }

  // 构造用于查找 cmd_id_config 的 key（去除路径和扩展名）
  std::string file_key_name;
  getFileKeyName(&file_key_name, file_name);

  // 查找当前文件对应的 CmdIdConfig（BEGIN/END 范围）
  auto config_it = cmd_id_config_map_.find(file_key_name);
  if (config_it == cmd_id_config_map_.end()) {
      LOG_ERROR << "can not find cmd_id config for " << *file_name;
      return -1;
  }
  const CmdIdConfig& cmd_id_config = config_it->second;

  // 遍历所有 message 定义
  for (uint32_t i = 0; i < msg_count; ++i) {
      const google::protobuf::Descriptor* msg_desc = file_desc->message_type(i);
      if (!msg_desc) continue;

      // 获取 CMD_ID 枚举值
      const google::protobuf::EnumValueDescriptor* enum_cmd_id = Descriptor::FindEnumValueByName<google::protobuf::EnumValueDescriptor>(msg_desc, "CMD_ID");
      if (!enum_cmd_id) {
          LOG_ERROR << "can not find CMD_ID in message: " << msg_desc->name();
          return -1;
      }
      uint32_t cmd_id = enum_cmd_id->number();

      // 检查是否重复注册 cmd_id
      if (cmd_to_name_map_.find(cmd_id) != cmd_to_name_map_.end()) {
          LOG_ERROR << "find repeat cmd_id=" << cmd_id << " in msg: " << msg_desc->name();
          return -1;
      }

      // 检查 cmd_id 是否在配置范围内
      if (!CmdIdConfig::isCmdIdValid(&cmd_id_config, cmd_id)) {
          LOG_ERROR << "invalid " << msg_desc->name() << "::CMD_ID=" << cmd_id << ", please check CmdIdConfig";
          return -1;
      }

      // 获取其他字段（如 is_allow_client、enet_channel_id 等）
      const google::protobuf::EnumValueDescriptor* enum_is_allow_client = Descriptor::FindEnumValueByName<google::protobuf::EnumValueDescriptor>(msg_desc, "is_allow_client");
      const google::protobuf::EnumValueDescriptor* enum_enet_reliable = Descriptor::FindEnumValueByName<google::protobuf::EnumValueDescriptor>(msg_desc, "enet_is_reliable");
      const google::protobuf::EnumValueDescriptor* enum_enet_channel_id = Descriptor::FindEnumValueByName<google::protobuf::EnumValueDescriptor>(msg_desc, "enet_channel_id");

      uint32_t is_allow_client = enum_is_allow_client ? enum_is_allow_client->number() : 0;
      uint32_t enet_reliable = enum_enet_reliable ? enum_enet_reliable->number() : 0;
      uint32_t enet_channel_id = enum_enet_channel_id ? enum_enet_channel_id->number() : 0;

      if (enet_reliable > 1 || is_allow_client > 1 || enet_channel_id > 4) {
          LOG_ERROR << "invalid is_allow_client=" << is_allow_client 
                    << ", enet_is_reliable=" << enet_reliable 
                    << ", enet_channel_id=" << enet_channel_id 
                    << " in msg " << msg_desc->name();
          return -1;
      }

      // 注册到全局 map 中
      cmd_to_name_map_[cmd_id] = msg_desc->name();
      name_to_cmd_map_[std::string("proto.") + msg_desc->name()] = cmd_id;

      cmd_to_channel_map_[cmd_id] = enet_channel_id;

      cmd_to_desc_map_[cmd_id] = msg_desc;

      ProtoCmdType cmd_type = getCmdTypeByName(msg_desc->name());
      cmd_to_type_map_[cmd_id] = cmd_type;

      if (is_allow_client) {
          allow_client_cmd_set_.insert(cmd_id);
      }
      if (enet_reliable) {
          reliable_cmd_set_.insert(cmd_id);
      }

      ++cmd_msg_count;
  }

  // 打印初始化日志
  if (is_show_init_log_) {
      LOG_INFO << "add " << cmd_msg_count << " cmd message from " << *file_name;
  }

  return result;
}

// Line 439: range 000000000C7FAA88-000000000C7FAE3F
int32_t ProtoUtils::splitCmdIdConfigName(
  const std::string& enum_name,
  std::string* file_key_name,
  CmdIdConfigType* type)
{
  size_t beginPos = enum_name.rfind("_BEGIN");
  size_t endPos = enum_name.rfind("_END");

  if (beginPos != std::string::npos && beginPos + 6 == enum_name.size())
  {
      *type = CMD_ID_CONFIG_BEGIN;
      *file_key_name = enum_name.substr(0, beginPos);
      return 0;
  }
  else if (endPos != std::string::npos && endPos + 4 == enum_name.size())
  {
      *type = CMD_ID_CONFIG_END;
      *file_key_name = enum_name.substr(0, endPos);
      return 0;
  }
  else
  {
      LOG_ERROR << "Invalid CmdIdConfig enum name: " << enum_name;
      return -1;
  }
}

// Line 479: range 000000000C7FD764-000000000C7FD93A
std::string *__fastcall ProtoUtils::getFileKeyName(std::string *retstr, const std::string *full_name)
{
  std::string::size_type v2; // r13
  const std::string *v4; // r12
  __int64 v5; // rax
  std::string::size_type v6; // rbp
  std::string::size_type M_string_length; // rax
  void *p_M_string_length; // rdi
  char *v9; // rax
  std::string::pointer M_p; // rsi
  const char *v11; // rsi
  char *v12; // rdx
  std::string::size_type i; // rdx
  unsigned __int64 v14; // rax
  void *v15; // rdi
  char v16; // cl
  __int64 v17; // rsi

  v4 = full_name;
  v5 = std::string::rfind(full_name, 47LL, -1LL);
  if ( v5 == -1 )
    v6 = 0LL;
  else
    v6 = v5 + 1;
  M_string_length = std::string::rfind(full_name, 46LL, -1LL);
  if ( v6 >= M_string_length || M_string_length == -1LL )
  {
    p_M_string_length = &full_name->_M_string_length;
    if ( *(_BYTE *)(((unsigned __int64)&full_name->_M_string_length >> 3) + 0x7FFF8000) )
    {
      __asan_report_load8(p_M_string_length);
      goto LABEL_16;
    }
    M_string_length = full_name->_M_string_length;
  }
  v9 = (char *)(M_string_length - v6);
  p_M_string_length = &full_name->_M_string_length;
  if ( *(_BYTE *)(((unsigned __int64)&full_name->_M_string_length >> 3) + 0x7FFF8000) )
  {
LABEL_16:
    __asan_report_load8(p_M_string_length);
LABEL_17:
    __asan_handle_no_return(p_M_string_length);
    std::__throw_out_of_range_fmt(
      "%s: __pos (which is %zu) > this->size() (which is %zu)",
      "basic_string::substr",
      v6,
      v2);
  }
  v2 = full_name->_M_string_length;
  if ( v6 > v2 )
    goto LABEL_17;
  if ( *(_BYTE *)(((unsigned __int64)retstr >> 3) + 0x7FFF8000) )
  {
    __asan_report_store8(retstr, 46LL);
    goto LABEL_19;
  }
  retstr->_M_dataplus._M_p = retstr->_anon_0._M_local_buf;
  if ( *(_BYTE *)(((unsigned __int64)full_name >> 3) + 0x7FFF8000) )
  {
LABEL_19:
    p_M_string_length = (void *)full_name;
    __asan_report_load8(full_name);
LABEL_20:
    __asan_handle_no_return(p_M_string_length);
    std::__throw_out_of_range_fmt(
      "%s: __pos (which is %zu) > this->size() (which is %zu)",
      "basic_string::basic_string",
      v6,
      (size_t)v4);
  }
  M_p = full_name->_M_dataplus._M_p;
  v4 = (const std::string *)v4->_M_string_length;
  if ( v6 > (unsigned __int64)v4 )
    goto LABEL_20;
  v11 = &M_p[v6];
  v12 = (char *)v4 - v6;
  if ( v9 < (char *)v4 - v6 )
    v12 = v9;
  std::string::_M_construct<char const*>(
    retstr,
    v11,
    &v12[(_QWORD)v11],
    (std::forward_iterator_tag)((unsigned __int64)retstr >> 3));
  for ( i = 0LL; ; ++i )
  {
    v15 = &retstr->_M_string_length;
    if ( *(_BYTE *)(((unsigned __int64)&retstr->_M_string_length >> 3) + 0x7FFF8000) )
    {
      __asan_report_load8(v15);
LABEL_22:
      v14 = __asan_report_load8(v15);
LABEL_23:
      if ( *(_BYTE *)v14 != 46 )
        continue;
      goto LABEL_31;
    }
    if ( i >= retstr->_M_string_length )
      break;
    v15 = retstr;
    if ( *(_BYTE *)(((unsigned __int64)retstr >> 3) + 0x7FFF8000) )
      goto LABEL_22;
    v14 = (unsigned __int64)&retstr->_M_dataplus._M_p[i];
    v16 = *(_BYTE *)((v14 >> 3) + 0x7FFF8000);
    v17 = (LOBYTE(retstr->_M_dataplus._M_p) + (_BYTE)i) & 7;
    if ( v16 > (char)v17 || !v16 )
      goto LABEL_23;
    v14 = __asan_report_load1(&retstr->_M_dataplus._M_p[i], v17, i);
LABEL_31:
    *(_BYTE *)v14 = 95;
  }
  return retstr;
};

// Line 517: range 000000000C7FC8EA-000000000C7FCCF6
unsigned __int64 __fastcall ProtoUtils::createMessage(unsigned __int64 a1, uint32_t cmd_id)
{
  unsigned __int64 v2; // rbp
  unsigned __int64 v3; // rbx
  unsigned __int64 v4; // r14
  unsigned __int64 v5; // r13
  const char *v6; // rsi
  std::_Rb_tree_header *M_node; // r12
  unsigned __int64 v8; // rdx
  __int64 v9; // rax
  unsigned __int64 v10; // rax
  _QWORD *v11; // rdi
  unsigned __int64 v12; // rdx
  unsigned __int64 v13; // rax
  __int64 v14; // rax
  unsigned __int64 v15; // rdi
  char v16; // dl
  char v17; // cl
  unsigned __int64 v18; // rdi
  void *v20; // rdi
  __int64 v21; // rax
  common::milog::MiLogStream v22; // [rsp+0h] [rbp-98h] BYREF
  char v23[120]; // [rsp+20h] [rbp-78h] BYREF

  v2 = a1;
  v3 = (unsigned __int64)v23;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v14 = __asan_stack_malloc_0(64LL);
    if ( v14 )
      v3 = v14;
  }
  v4 = v3 + 64;
  *(_QWORD *)v3 = 1102416563LL;
  *(_QWORD *)(v3 + 8) = "1 32 4 10 cmd_id:516";
  *(_QWORD *)(v3 + 16) = ProtoUtils::createMessage;
  v5 = v3 >> 3;
  *(_DWORD *)(v5 + 2147450880) = -235802127;
  *(_DWORD *)(v5 + 2147450884) = -202116348;
  *(_DWORD *)(v3 + 32) = cmd_id;
  v6 = (const char *)(v3 + 32);
  M_node = (std::_Rb_tree_header *)std::_Rb_tree<unsigned int,std::pair<unsigned int const,google::protobuf::Descriptor const*>,std::_Select1st<std::pair<unsigned int const,google::protobuf::Descriptor const*>>,std::less<unsigned int>,std::allocator<std::pair<unsigned int const,google::protobuf::Descriptor const*>>>::find(
                                     &ProtoUtils::cmd_to_desc_map_._M_t,
                                     (const unsigned int *)(v3 + 32))._M_node;
  if ( M_node == &ProtoUtils::cmd_to_desc_map_._M_t._M_impl.std::_Rb_tree_header )
  {
    M_node = (std::_Rb_tree_header *)&v22;
    common::milog::MiLogStream::MiLogStream(
      &v22,
      &common::milog::MiLogDefault::default_log_obj_,
      3u,
      "src/proto_utils.cpp",
      "createMessage",
      522);
    v6 = "can not find desc for cmd_id=%u";
    common::milog::MiLogStream::operator()(&v22, "can not find desc for cmd_id=%u", *(unsigned int *)(v3 + 32));
    common::milog::MiLogStream::~MiLogStream(&v22);
    if ( *(_BYTE *)((a1 >> 3) + 0x7FFF8000) )
    {
      __asan_report_store8(a1, "can not find desc for cmd_id=%u");
    }
    else
    {
      *(_QWORD *)a1 = 0LL;
      a1 += 8LL;
      if ( !*(_BYTE *)(((v2 + 8) >> 3) + 0x7FFF8000) )
      {
        *(_QWORD *)(v2 + 8) = 0LL;
        goto LABEL_39;
      }
    }
    __asan_report_store8(a1, "can not find desc for cmd_id=%u");
    goto LABEL_19;
  }
  a1 = google::protobuf::MessageFactory::generated_factory((google::protobuf::MessageFactory *)&ProtoUtils::cmd_to_desc_map_);
  if ( *(_BYTE *)((a1 >> 3) + 0x7FFF8000) )
  {
LABEL_19:
    __asan_report_load8(a1);
    goto LABEL_20;
  }
  v8 = *(_QWORD *)a1 + 16LL;
  if ( *(_BYTE *)((v8 >> 3) + 0x7FFF8000) )
  {
LABEL_20:
    v9 = __asan_report_load8(v8);
    goto LABEL_21;
  }
  v9 = (__int64)&M_node[1];
  if ( *(_BYTE *)(((unsigned __int64)&M_node[1] >> 3) + 0x7FFF8000) )
  {
LABEL_21:
    __asan_report_load8(v9);
    goto LABEL_22;
  }
  v6 = *(const char **)&M_node[1]._M_header._M_color;
  v10 = (*(__int64 (__fastcall **)(unsigned __int64, const char *))(*(_QWORD *)a1 + 16LL))(a1, v6);
  v11 = (_QWORD *)v10;
  if ( !v10 )
  {
LABEL_22:
    if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
    {
      v11 = (_QWORD *)v2;
      __asan_report_store8(v2, v6);
    }
    else
    {
      *(_QWORD *)v2 = 0LL;
      v11 = (_QWORD *)(v2 + 8);
      if ( !*(_BYTE *)(((v2 + 8) >> 3) + 0x7FFF8000) )
      {
        *(_QWORD *)(v2 + 8) = 0LL;
        goto LABEL_39;
      }
    }
    __asan_report_store8(v11, v6);
    goto LABEL_27;
  }
  if ( *(_BYTE *)((v10 >> 3) + 0x7FFF8000) )
  {
LABEL_27:
    __asan_report_load8(v11);
    goto LABEL_28;
  }
  v12 = *(_QWORD *)v10 + 24LL;
  if ( *(_BYTE *)((v12 >> 3) + 0x7FFF8000) )
  {
LABEL_28:
    __asan_report_load8(v12);
    goto LABEL_29;
  }
  M_node = (std::_Rb_tree_header *)(*(__int64 (**)(void))(*(_QWORD *)v10 + 24LL))();
  if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
  {
LABEL_29:
    __asan_report_store8(v2, v6);
    goto LABEL_30;
  }
  *(_QWORD *)v2 = M_node;
  v4 = v2 + 8;
  if ( *(_BYTE *)(((v2 + 8) >> 3) + 0x7FFF8000) )
  {
LABEL_30:
    v13 = __asan_report_store8(v4, v6);
    goto LABEL_31;
  }
  *(_QWORD *)(v2 + 8) = 0LL;
  v13 = operator new(0x18uLL);
LABEL_31:
  v15 = v13 + 8;
  v16 = *(_BYTE *)(((v13 + 8) >> 3) + 0x7FFF8000);
  if ( v16 && v16 <= 3 )
  {
    __asan_report_store4(v15, v6);
LABEL_43:
    v13 = __asan_report_store4(v15, v6);
    goto LABEL_44;
  }
  *(_DWORD *)(v13 + 8) = 1;
  v15 = v13 + 12;
  v17 = *(_BYTE *)(((v13 + 12) >> 3) + 0x7FFF8000);
  if ( (char)(((v13 + 12) & 7) + 3) >= v17 && v17 )
    goto LABEL_43;
  *(_DWORD *)(v13 + 12) = 1;
  if ( *(_BYTE *)((v13 >> 3) + 0x7FFF8000) )
  {
LABEL_44:
    v18 = v13;
    __asan_report_store8(v13, v6);
    goto LABEL_45;
  }
  *(_QWORD *)v13 = &`vtable for std::_Sp_counted_ptr<google::protobuf::Message *,(__gnu_cxx::_Lock_policy)2> + 2;
  v18 = v13 + 16;
  if ( *(_BYTE *)(((v13 + 16) >> 3) + 0x7FFF8000) )
  {
LABEL_45:
    __asan_report_store8(v18, v6);
LABEL_46:
    v20 = (void *)__asan_report_store8(v4, v6);
    __cxa_begin_catch(v20);
    if ( M_node )
    {
      if ( *(_BYTE *)(((unsigned __int64)M_node >> 3) + 0x7FFF8000) )
        __asan_report_load8(M_node);
      v21 = *(_QWORD *)&M_node->_M_header._M_color;
      if ( *(_BYTE *)(((unsigned __int64)(*(_QWORD *)&M_node->_M_header._M_color + 8LL) >> 3) + 0x7FFF8000) )
        v21 = __asan_report_load8(*(_QWORD *)&M_node->_M_header._M_color + 8LL);
      v20 = M_node;
      (*(void (__fastcall **)(std::_Rb_tree_header *))(v21 + 8))(M_node);
    }
    __asan_handle_no_return(v20);
    __cxa_rethrow();
  }
  *(_QWORD *)(v13 + 16) = M_node;
  if ( *(_BYTE *)((v4 >> 3) + 0x7FFF8000) )
    goto LABEL_46;
  *(_QWORD *)(v2 + 8) = v13;
LABEL_39:
  if ( v23 == (char *)v3 )
  {
    *(_QWORD *)((v3 >> 3) + 0x7FFF8000) = 0LL;
  }
  else
  {
    *(_QWORD *)v3 = 1172321806LL;
    *(_QWORD *)((v3 >> 3) + 0x7FFF8000) = 0xF5F5F5F5F5F5F5F5LL;
  }
  return v2;
};

// Line 538: range 000000000C7FC24A-000000000C7FC31C
const std::string& ProtoUtils::getCmdName(uint32_t cmd_id) {
  // 查找 cmd_id 对应的命令名称
  auto it = ProtoUtils::cmd_to_name_map_.find(cmd_id);
  
  // 如果未找到对应的 cmd_id，则返回默认命令名称
  if (it == ProtoUtils::cmd_to_name_map_.end()) {
      return ProtoUtils::default_cmd_name;
  }
  
  // 返回找到的命令名称
  return it->second;
}

// Line 549: range 000000000C7FCCFC-000000000C7FCD42
uint32_t __fastcall ProtoUtils::getCmdId(const std::string *cmd_name)
{
  std::_Rb_tree<std::string,std::pair<const std::string,unsigned int>,std::_Select1st<std::pair<const std::string,unsigned int> >,std::less<std::string >,std::allocator<std::pair<const std::string,unsigned int> > >::iterator v1; // rax
  char v2; // dl

  v1._M_node = std::_Rb_tree<std::string,std::pair<std::string const,unsigned int>,std::_Select1st<std::pair<std::string const,unsigned int>>,std::less<std::string>,std::allocator<std::pair<std::string const,unsigned int>>>::find(
                 &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t,
                 cmd_name)._M_node;
  if ( (std::_Rb_tree_header *)v1._M_node != &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header )
  {
    v2 = *(_BYTE *)(((unsigned __int64)&v1._M_node[2] >> 3) + 0x7FFF8000);
    if ( !v2 || v2 > 3 )
      return v1._M_node[2]._M_color;
    __asan_report_load4(&v1._M_node[2]);
  }
  return 0;
};

// Line 560: range 000000000C7FCD44-000000000C7FCE40
ProtoCmdType __fastcall ProtoUtils::getCmdType(uint32_t cmd_id)
{
  unsigned __int64 v1; // rbx
  unsigned __int64 v2; // rbp
  std::_Rb_tree<unsigned int,std::pair<unsigned int const,ProtoCmdType>,std::_Select1st<std::pair<unsigned int const,ProtoCmdType> >,std::less<unsigned int>,std::allocator<std::pair<unsigned int const,ProtoCmdType> > >::iterator v3; // rax
  char v4; // cl
  ProtoCmdType result; // eax
  __int64 v6; // rax
  _BYTE v7[104]; // [rsp+0h] [rbp-68h] BYREF

  v1 = (unsigned __int64)v7;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v6 = __asan_stack_malloc_0(64LL);
    if ( v6 )
      v1 = v6;
  }
  *(_QWORD *)v1 = 1102416563LL;
  *(_QWORD *)(v1 + 8) = "1 32 4 10 cmd_id:559";
  *(_QWORD *)(v1 + 16) = ProtoUtils::getCmdType;
  v2 = v1 >> 3;
  *(_DWORD *)(v2 + 2147450880) = -235802127;
  *(_DWORD *)(v2 + 2147450884) = -202116348;
  *(_DWORD *)(v1 + 32) = cmd_id;
  v3._M_node = std::_Rb_tree<unsigned int,std::pair<unsigned int const,ProtoCmdType>,std::_Select1st<std::pair<unsigned int const,ProtoCmdType>>,std::less<unsigned int>,std::allocator<std::pair<unsigned int const,ProtoCmdType>>>::find(
                 &ProtoUtils::cmd_to_type_map_._M_t,
                 (const unsigned int *)(v1 + 32))._M_node;
  if ( (std::_Rb_tree_header *)v3._M_node != &ProtoUtils::cmd_to_type_map_._M_t._M_impl.std::_Rb_tree_header )
  {
    v4 = *(_BYTE *)(((unsigned __int64)(&v3._M_node[1]._M_color + 1) >> 3) + 0x7FFF8000);
    if ( (char)(((LOBYTE(v3._M_node) + 36) & 7) + 3) < v4 || !v4 )
    {
      result = *((_DWORD *)&v3._M_node[1]._M_color + 1);
      goto LABEL_6;
    }
    __asan_report_load4(&v3._M_node[1]._M_color + 1);
  }
  result = PROTO_CMD_NONE;
LABEL_6:
  if ( v7 == (_BYTE *)v1 )
  {
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0LL;
  }
  else
  {
    *(_QWORD *)v1 = 1172321806LL;
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0xF5F5F5F5F5F5F5F5LL;
  }
  return result;
};

// Line 573: range 000000000C7FCE42-000000000C7FCF3E
uint32_t __fastcall ProtoUtils::getEnetChannelId(uint32_t cmd_id)
{
  unsigned __int64 v1; // rbx
  unsigned __int64 v2; // rbp
  std::_Rb_tree<unsigned int,std::pair<unsigned int const,unsigned int>,std::_Select1st<std::pair<unsigned int const,unsigned int> >,std::less<unsigned int>,std::allocator<std::pair<unsigned int const,unsigned int> > >::iterator v3; // rax
  char v4; // cl
  uint32_t result; // eax
  __int64 v6; // rax
  _BYTE v7[104]; // [rsp+0h] [rbp-68h] BYREF

  v1 = (unsigned __int64)v7;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v6 = __asan_stack_malloc_0(64LL);
    if ( v6 )
      v1 = v6;
  }
  *(_QWORD *)v1 = 1102416563LL;
  *(_QWORD *)(v1 + 8) = "1 32 4 10 cmd_id:572";
  *(_QWORD *)(v1 + 16) = ProtoUtils::getEnetChannelId;
  v2 = v1 >> 3;
  *(_DWORD *)(v2 + 2147450880) = -235802127;
  *(_DWORD *)(v2 + 2147450884) = -202116348;
  *(_DWORD *)(v1 + 32) = cmd_id;
  v3._M_node = std::_Rb_tree<unsigned int,std::pair<unsigned int const,unsigned int>,std::_Select1st<std::pair<unsigned int const,unsigned int>>,std::less<unsigned int>,std::allocator<std::pair<unsigned int const,unsigned int>>>::find(
                 &ProtoUtils::cmd_to_channel_map_._M_t,
                 (const unsigned int *)(v1 + 32))._M_node;
  if ( (std::_Rb_tree_header *)v3._M_node != &ProtoUtils::cmd_to_channel_map_._M_t._M_impl.std::_Rb_tree_header )
  {
    v4 = *(_BYTE *)(((unsigned __int64)(&v3._M_node[1]._M_color + 1) >> 3) + 0x7FFF8000);
    if ( (char)(((LOBYTE(v3._M_node) + 36) & 7) + 3) < v4 || !v4 )
    {
      result = *((_DWORD *)&v3._M_node[1]._M_color + 1);
      goto LABEL_6;
    }
    __asan_report_load4(&v3._M_node[1]._M_color + 1);
  }
  result = 0;
LABEL_6:
  if ( v7 == (_BYTE *)v1 )
  {
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0LL;
  }
  else
  {
    *(_QWORD *)v1 = 1172321806LL;
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0xF5F5F5F5F5F5F5F5LL;
  }
  return result;
};

// Line 584: range 000000000C7FCF40-000000000C7FD012
bool __fastcall ProtoUtils::isAllowClientSend(uint32_t cmd_id)
{
  unsigned __int64 v1; // rbx
  unsigned __int64 v2; // rbp
  bool result; // al
  __int64 v4; // rax
  _BYTE v5[104]; // [rsp+0h] [rbp-68h] BYREF

  v1 = (unsigned __int64)v5;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v4 = __asan_stack_malloc_0(64LL);
    if ( v4 )
      v1 = v4;
  }
  *(_QWORD *)v1 = 1102416563LL;
  *(_QWORD *)(v1 + 8) = "1 32 4 10 cmd_id:583";
  *(_QWORD *)(v1 + 16) = ProtoUtils::isAllowClientSend;
  v2 = v1 >> 3;
  *(_DWORD *)(v2 + 2147450880) = -235802127;
  *(_DWORD *)(v2 + 2147450884) = -202116348;
  *(_DWORD *)(v1 + 32) = cmd_id;
  result = &ProtoUtils::allow_client_cmd_set_._M_t._M_impl.std::_Rb_tree_header != (std::_Rb_tree_header *)std::_Rb_tree<unsigned int,unsigned int,std::_Identity<unsigned int>,std::less<unsigned int>,std::allocator<unsigned int>>::find(&ProtoUtils::allow_client_cmd_set_._M_t, (const unsigned int *)(v1 + 32))._M_node;
  if ( v5 == (_BYTE *)v1 )
  {
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0LL;
  }
  else
  {
    *(_QWORD *)v1 = 1172321806LL;
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0xF5F5F5F5F5F5F5F5LL;
  }
  return result;
};

// Line 590: range 000000000C7FD014-000000000C7FD0E6
bool __fastcall ProtoUtils::isEnetReliable(uint32_t cmd_id)
{
  unsigned __int64 v1; // rbx
  unsigned __int64 v2; // rbp
  bool result; // al
  __int64 v4; // rax
  _BYTE v5[104]; // [rsp+0h] [rbp-68h] BYREF

  v1 = (unsigned __int64)v5;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v4 = __asan_stack_malloc_0(64LL);
    if ( v4 )
      v1 = v4;
  }
  *(_QWORD *)v1 = 1102416563LL;
  *(_QWORD *)(v1 + 8) = "1 32 4 10 cmd_id:589";
  *(_QWORD *)(v1 + 16) = ProtoUtils::isEnetReliable;
  v2 = v1 >> 3;
  *(_DWORD *)(v2 + 2147450880) = -235802127;
  *(_DWORD *)(v2 + 2147450884) = -202116348;
  *(_DWORD *)(v1 + 32) = cmd_id;
  result = &ProtoUtils::reliable_cmd_set_._M_t._M_impl.std::_Rb_tree_header != (std::_Rb_tree_header *)std::_Rb_tree<unsigned int,unsigned int,std::_Identity<unsigned int>,std::less<unsigned int>,std::allocator<unsigned int>>::find(&ProtoUtils::reliable_cmd_set_._M_t, (const unsigned int *)(v1 + 32))._M_node;
  if ( v5 == (_BYTE *)v1 )
  {
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0LL;
  }
  else
  {
    *(_QWORD *)v1 = 1172321806LL;
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0xF5F5F5F5F5F5F5F5LL;
  }
  return result;
};

// Line 596: range 000000000C7FD0E8-000000000C7FD1BA
const std::string *__fastcall ProtoUtils::getRetcodeName[abi:cxx11](int32_t retcode)
{
  unsigned __int64 v1; // rbx
  unsigned __int64 v2; // rbp
  std::_Rb_tree<int,std::pair<int const,std::string >,std::_Select1st<std::pair<int const,std::string > >,std::less<int>,std::allocator<std::pair<int const,std::string > > >::iterator v3; // rax
  const std::string *result; // rax
  __int64 v5; // rax
  _BYTE v6[104]; // [rsp+0h] [rbp-68h] BYREF

  v1 = (unsigned __int64)v6;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v5 = __asan_stack_malloc_0(64LL);
    if ( v5 )
      v1 = v5;
  }
  *(_QWORD *)v1 = 1102416563LL;
  *(_QWORD *)(v1 + 8) = "1 32 4 11 retcode:595";
  *(_QWORD *)(v1 + 16) = ProtoUtils::getRetcodeName[abi:cxx11];
  v2 = v1 >> 3;
  *(_DWORD *)(v2 + 2147450880) = -235802127;
  *(_DWORD *)(v2 + 2147450884) = -202116348;
  *(_DWORD *)(v1 + 32) = retcode;
  v3._M_node = std::_Rb_tree<int,std::pair<int const,std::string>,std::_Select1st<std::pair<int const,std::string>>,std::less<int>,std::allocator<std::pair<int const,std::string>>>::find(
                 &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t,
                 (const int *)(v1 + 32))._M_node;
  if ( (std::_Rb_tree_header *)v3._M_node == &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header )
    result = &ProtoUtils::default_retcode_name_[abi:cxx11];
  else
    result = (const std::string *)&v3._M_node[1]._M_parent;
  if ( v6 == (_BYTE *)v1 )
  {
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0LL;
  }
  else
  {
    *(_QWORD *)v1 = 1172321806LL;
    *(_QWORD *)((v1 >> 3) + 0x7FFF8000) = 0xF5F5F5F5F5F5F5F5LL;
  }
  return result;
};

// Line 607: range 000000000C7FC31E-000000000C7FC8E4
__int64 __fastcall ProtoUtils::convertPacketToString(common::minet::PacketPtr packet_ptr, std::string *str)
{
  unsigned __int64 M_ptr; // rbp
  std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2> *M_pi; // rbx
  unsigned __int64 v4; // r13
  _DWORD *v5; // r14
  char v6; // al
  __int64 v7; // rdx
  char v8; // dl
  unsigned __int64 v9; // rax
  int (**v10)(...); // rdx
  unsigned __int64 v11; // rdi
  char v12; // cl
  char v13; // si
  char v14; // cl
  const char *v15; // r9
  _Atomic_word *p_M_use_count; // rdi
  char v17; // al
  char v18; // r15
  size_t v19; // rdx
  _Atomic_word *v20; // rdi
  __int64 v21; // rax
  __int64 result; // rax
  _Atomic_word *v23; // rdi
  char *v24; // rdi
  common::milog::MiLogStream v25; // [rsp+10h] [rbp-158h] BYREF
  char v26[312]; // [rsp+30h] [rbp-138h] BYREF

  M_ptr = (unsigned __int64)packet_ptr._M_ptr;
  M_pi = packet_ptr._M_refcount._M_pi;
  v4 = (unsigned __int64)v26;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v21 = __asan_stack_malloc_2(256LL);
    if ( v21 )
      v4 = v21;
  }
  *(_QWORD *)v4 = 1102416563LL;
  *(_QWORD *)(v4 + 8) = "2 32 32 18 head_debug_str:622 96 128 7 buf:616";
  *(_QWORD *)(v4 + 16) = ProtoUtils::convertPacketToString;
  v5 = (_DWORD *)(v4 >> 3);
  v5[536862720] = -235802127;
  v5[536862722] = -218959118;
  v5[536862727] = -202116109;
  if ( *(_BYTE *)(((unsigned __int64)packet_ptr._M_ptr >> 3) + 0x7FFF8000) )
  {
    __asan_report_load8(packet_ptr._M_ptr);
    goto LABEL_32;
  }
  if ( !packet_ptr._M_ptr->_vptr_Packet )
  {
LABEL_32:
    common::milog::MiLogStream::MiLogStream(
      &v25,
      &common::milog::MiLogDefault::default_log_obj_,
      3u,
      "src/proto_utils.cpp",
      "convertPacketToString",
      610);
    common::milog::MiLogStream::operator()(&v25, "packet is null");
    common::milog::MiLogStream::~MiLogStream(&v25);
    result = 0xFFFFFFFFLL;
    goto LABEL_63;
  }
  if ( *(_BYTE *)(((unsigned __int64)&packet_ptr._M_refcount._M_pi->_M_use_count >> 3) + 0x7FFF8000) )
  {
    __asan_report_store8(&packet_ptr._M_refcount._M_pi->_M_use_count, packet_ptr._M_refcount._M_pi);
    goto LABEL_34;
  }
  *(_QWORD *)&packet_ptr._M_refcount._M_pi->_M_use_count = 0LL;
  if ( *(_BYTE *)(((unsigned __int64)packet_ptr._M_refcount._M_pi >> 3) + 0x7FFF8000) )
  {
LABEL_34:
    packet_ptr._M_ptr = (std::__shared_ptr<common::minet::Packet,(__gnu_cxx::_Lock_policy)2>::element_type *)packet_ptr._M_refcount._M_pi;
    __asan_report_load8(packet_ptr._M_refcount._M_pi);
LABEL_35:
    __asan_report_store1(packet_ptr._M_ptr, packet_ptr._M_refcount._M_pi, v7);
LABEL_36:
    __asan_report_load2(packet_ptr._M_ptr);
    goto LABEL_37;
  }
  packet_ptr._M_ptr = (std::__shared_ptr<common::minet::Packet,(__gnu_cxx::_Lock_policy)2>::element_type *)packet_ptr._M_refcount._M_pi->_vptr__Sp_counted_base;
  v6 = *(_BYTE *)(((unsigned __int64)packet_ptr._M_refcount._M_pi->_vptr__Sp_counted_base >> 3) + 0x7FFF8000);
  v7 = (__int64)packet_ptr._M_refcount._M_pi->_vptr__Sp_counted_base & 7;
  if ( v6 <= (char)v7 && v6 )
    goto LABEL_35;
  LOBYTE(packet_ptr._M_ptr->_vptr_Packet) = 0;
  packet_ptr._M_ptr = (std::__shared_ptr<common::minet::Packet,(__gnu_cxx::_Lock_policy)2>::element_type *)(*(_QWORD *)M_ptr + 8LL);
  v8 = *(_BYTE *)(((unsigned __int64)packet_ptr._M_ptr >> 3) + 0x7FFF8000);
  if ( v8 && v8 <= 1 )
    goto LABEL_36;
  v9 = (unsigned __int64)ProtoUtils::getCmdName[abi:cxx11](*(unsigned __int16 *)(*(_QWORD *)M_ptr + 8LL));
  if ( *(_BYTE *)((M_ptr >> 3) + 0x7FFF8000) )
  {
LABEL_37:
    v11 = M_ptr;
    __asan_report_load8(M_ptr);
    goto LABEL_38;
  }
  v10 = *(int (***)(...))M_ptr;
  v11 = *(_QWORD *)M_ptr + 200LL;
  if ( *(_BYTE *)((v11 >> 3) + 0x7FFF8000) )
  {
LABEL_38:
    __asan_report_load8(v11);
LABEL_39:
    __asan_report_load4(v11);
LABEL_40:
    __asan_report_load4(v11);
LABEL_41:
    v9 = __asan_report_load4(v11);
    goto LABEL_42;
  }
  v11 = (unsigned __int64)(v10 + 24);
  v12 = *(_BYTE *)(((unsigned __int64)(v10 + 24) >> 3) + 0x7FFF8000);
  if ( v12 && v12 <= 3 )
    goto LABEL_39;
  v11 = (unsigned __int64)v10 + 188;
  v13 = *(_BYTE *)((((unsigned __int64)v10 + 188) >> 3) + 0x7FFF8000);
  if ( (char)((((_BYTE)v10 - 68) & 7) + 3) >= v13 && v13 )
    goto LABEL_40;
  v11 = (unsigned __int64)(v10 + 23);
  v14 = *(_BYTE *)(((unsigned __int64)(v10 + 23) >> 3) + 0x7FFF8000);
  if ( v14 && v14 <= 3 )
    goto LABEL_41;
  if ( *(_BYTE *)((v9 >> 3) + 0x7FFF8000) )
  {
LABEL_42:
    p_M_use_count = (_Atomic_word *)v9;
    __asan_report_load8(v9);
LABEL_43:
    __asan_report_load2(p_M_use_count);
LABEL_44:
    __asan_report_load4(p_M_use_count);
    goto LABEL_45;
  }
  v15 = *(const char **)v9;
  p_M_use_count = (_Atomic_word *)(v10 + 1);
  v17 = *(_BYTE *)(((unsigned __int64)(v10 + 1) >> 3) + 0x7FFF8000);
  if ( v17 && v17 <= 1 )
    goto LABEL_43;
  p_M_use_count = (_Atomic_word *)v10 + 53;
  v18 = *(_BYTE *)((((unsigned __int64)v10 + 212) >> 3) + 0x7FFF8000);
  if ( (char)((((_BYTE)v10 - 44) & 7) + 3) >= v18 && v18 )
    goto LABEL_44;
  snprintf(
    (char *)(v4 + 96),
    0x80uLL,
    "uid:%u, cmd_id:%u, cmd_name:%s, packet_id:%u, rpc_id:%u, client_sequence_id:%lu sent_ms:%lu",
    *((unsigned int *)v10 + 53),
    *((unsigned __int16 *)v10 + 4),
    v15,
    *((unsigned int *)v10 + 46),
    *((unsigned int *)v10 + 47),
    *((unsigned int *)v10 + 48),
    v10[25]);
  v19 = strlen((const char *)(v4 + 96));
  p_M_use_count = &M_pi->_M_use_count;
  if ( *(_BYTE *)(((unsigned __int64)&M_pi->_M_use_count >> 3) + 0x7FFF8000) )
  {
LABEL_45:
    __asan_report_load8(p_M_use_count);
LABEL_46:
    __asan_handle_no_return(p_M_use_count);
    std::__throw_length_error("basic_string::append");
  }
  if ( v19 > 0x3FFFFFFFFFFFFFFFLL - *(_QWORD *)&M_pi->_M_use_count )
    goto LABEL_46;
  std::string::_M_append(M_pi, (const char *)(v4 + 96));
  if ( *(_BYTE *)((M_ptr >> 3) + 0x7FFF8000) )
  {
    v20 = (_Atomic_word *)M_ptr;
    __asan_report_load8(M_ptr);
    goto LABEL_48;
  }
  common::minet::Packet::getHeadDebugString[abi:cxx11](
    (std::string *)(v4 + 32),
    *(const common::minet::Packet *const *)M_ptr);
  v20 = &M_pi->_M_use_count;
  if ( *(_BYTE *)(((unsigned __int64)&M_pi->_M_use_count >> 3) + 0x7FFF8000) )
  {
LABEL_48:
    __asan_report_load8(v20);
LABEL_49:
    __asan_handle_no_return(v20);
    std::__throw_length_error("basic_string::append");
  }
  if ( (unsigned __int64)(0x3FFFFFFFFFFFFFFFLL - *(_QWORD *)&M_pi->_M_use_count) <= 6 )
    goto LABEL_49;
  std::string::_M_append(M_pi, "\nHEAD: ", 7LL);
  std::string::_M_append(M_pi, *(const char **)(v4 + 32), *(_QWORD *)(v4 + 40));
  v23 = &M_pi->_M_use_count;
  if ( *(_BYTE *)(((unsigned __int64)&M_pi->_M_use_count >> 3) + 0x7FFF8000) )
  {
    __asan_report_load8(v23);
LABEL_54:
    __asan_handle_no_return(v23);
    std::__throw_length_error("basic_string::append");
  }
  if ( (unsigned __int64)(0x3FFFFFFFFFFFFFFFLL - *(_QWORD *)&M_pi->_M_use_count) <= 6 )
    goto LABEL_54;
  std::string::_M_append(M_pi, "\nBODY: ", 7LL);
  if ( *(_BYTE *)((M_ptr >> 3) + 0x7FFF8000) )
    __asan_report_load8(M_ptr);
  else
    common::minet::Packet::getProtoDebugString[abi:cxx11](
      (std::string *)&v25,
      *(const common::minet::Packet *const *)M_ptr);
  std::string::_M_append(M_pi, (const char *)v25.log_, v25.ostr_ptr_._M_ptr);
  if ( (std::__shared_count<(__gnu_cxx::_Lock_policy)2> *)v25.log_ != &v25.ostr_ptr_._M_refcount )
    operator delete(v25.log_);
  v24 = *(char **)(v4 + 32);
  if ( v24 != (char *)(v4 + 48) )
    operator delete(v24);
  result = 0LL;
LABEL_63:
  if ( v26 == (char *)v4 )
  {
    *(_DWORD *)((v4 >> 3) + 0x7FFF8000) = 0;
    *(_DWORD *)((v4 >> 3) + 0x7FFF8008) = 0;
    *(_DWORD *)((v4 >> 3) + 0x7FFF801C) = 0;
  }
  else
  {
    *(_QWORD *)v4 = 1172321806LL;
    *(_QWORD *)((v4 >> 3) + 0x7FFF8000) = 0xF5F5F5F5F5F5F5F5LL;
    *(_QWORD *)((v4 >> 3) + 0x7FFF8008) = 0xF5F5F5F5F5F5F5F5LL;
    *(_QWORD *)((v4 >> 3) + 0x7FFF8010) = 0xF5F5F5F5F5F5F5F5LL;
    *(_QWORD *)((v4 >> 3) + 0x7FFF8018) = 0xF5F5F5F5F5F5F5F5LL;
  }
  return result;
};

// Line 634: range 000000000C7FD1BC-000000000C7FD285
__int64 __fastcall ProtoUtils::getRetcodeValue(const std::string *a1)
{
  std::_Rb_tree<std::string,std::pair<const std::string,int>,std::_Select1st<std::pair<const std::string,int> >,std::less<std::string >,std::allocator<std::pair<const std::string,int> > >::iterator v1; // rax
  char v2; // dl
  struct _Unwind_Exception *v4; // rbx
  common::milog::MiLogStream v5; // [rsp+0h] [rbp-38h] BYREF

  v1._M_node = std::_Rb_tree<std::string,std::pair<std::string const,int>,std::_Select1st<std::pair<std::string const,int>>,std::less<std::string>,std::allocator<std::pair<std::string const,int>>>::find(
                 &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t,
                 a1)._M_node;
  if ( (std::_Rb_tree_header *)v1._M_node == &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header )
  {
    common::milog::MiLogStream::MiLogStream(
      &v5,
      &common::milog::MiLogDefault::default_log_obj_,
      3u,
      "src/proto_utils.cpp",
      "getRetcodeValue",
      638);
    if ( *(_BYTE *)(((unsigned __int64)a1 >> 3) + 0x7FFF8000) )
      __asan_report_load8(a1);
    else
      common::milog::MiLogStream::operator()(&v5, "can not find Retcode name=%s", a1->_M_dataplus._M_p);
    common::milog::MiLogStream::~MiLogStream(&v5);
    return 0xFFFFFFFFLL;
  }
  else
  {
    v2 = *(_BYTE *)(((unsigned __int64)&v1._M_node[2] >> 3) + 0x7FFF8000);
    if ( v2 )
    {
      if ( v2 <= 3 )
      {
        v4 = (struct _Unwind_Exception *)__asan_report_load4(&v1._M_node[2]);
        common::milog::MiLogStream::~MiLogStream(&v5);
        __asan_handle_no_return(&v5);
        _Unwind_Resume(v4);
      }
    }
    return (unsigned int)v1._M_node[2]._M_color;
  }
};

// Line 646: range 000000000C7FD93C-000000000C7FDB3A
ProtoCmdType __fastcall ProtoUtils::getCmdTypeByName(const std::string *name)
{
  char v1; // cl
  unsigned __int64 v3; // r12
  unsigned __int64 v4; // r13
  std::string::size_type v5; // rdx
  std::string::size_type v6; // r8
  __int64 v7; // rax
  unsigned __int64 v8; // rax
  void *p_M_string_length; // rdi
  __int64 v10; // rsi
  bool v11; // zf
  const std::string *v12; // r8
  const char *v13; // rdx
  ProtoCmdType v14; // ebx
  std::string::$CFBEC286C7F52157F7E59FC354047095 *v15; // rdi
  _BYTE v17[152]; // [rsp+0h] [rbp-98h] BYREF

  v3 = (unsigned __int64)v17;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v7 = __asan_stack_malloc_1(96LL);
    if ( v7 )
      v3 = v7;
  }
  *(_QWORD *)v3 = 1102416563LL;
  *(_QWORD *)(v3 + 8) = "1 32 32 13 type_name:658";
  *(_QWORD *)(v3 + 16) = ProtoUtils::getCmdTypeByName;
  v4 = v3 >> 3;
  *(_DWORD *)(v4 + 2147450880) = -235802127;
  *(_DWORD *)(v4 + 2147450888) = -202116109;
  v5 = 0LL;
  v6 = 0LL;
  while ( 1 )
  {
    p_M_string_length = &name->_M_string_length;
    if ( *(_BYTE *)(((unsigned __int64)&name->_M_string_length >> 3) + 0x7FFF8000) )
    {
      __asan_report_load8(p_M_string_length);
LABEL_6:
      v8 = __asan_report_load8(p_M_string_length);
      goto LABEL_7;
    }
    if ( v5 >= name->_M_string_length )
      goto LABEL_16;
    p_M_string_length = (void *)name;
    if ( *(_BYTE *)(((unsigned __int64)name >> 3) + 0x7FFF8000) )
      goto LABEL_6;
    v8 = (unsigned __int64)&name->_M_dataplus._M_p[v5];
    v1 = *(_BYTE *)((v8 >> 3) + 0x7FFF8000);
    v10 = (LOBYTE(name->_M_dataplus._M_p) + (_BYTE)v5) & 7;
    if ( v1 <= (char)v10 )
    {
      if ( v1 )
        break;
    }
LABEL_7:
    if ( (unsigned __int8)(*(_BYTE *)v8 - 65) <= 0x19u )
      v6 = v5;
    ++v5;
  }
  __asan_report_load1(&name->_M_dataplus._M_p[v5], v10, v5);
LABEL_16:
  if ( *(_BYTE *)(((unsigned __int64)name >> 3) + 0x7FFF8000) )
  {
    __asan_report_load8(name);
  }
  else
  {
    v11 = &name->_M_dataplus._M_p[v6] == 0;
    v12 = (const std::string *)&name->_M_dataplus._M_p[v6];
    name = v12;
    *(_QWORD *)(v3 + 32) = v3 + 48;
    if ( !v11 )
    {
      v13 = (char *)v12 + strlen((const char *)v12);
      goto LABEL_19;
    }
  }
  v13 = &v12[-1]._anon_0._M_local_buf[15];
LABEL_19:
  std::string::_M_construct<char const*>(
    (std::string *const)(v3 + 32),
    (const char *)name,
    v13,
    (std::forward_iterator_tag)v1);
  if ( !(unsigned int)std::string::compare(v3 + 32, &off_19E8C4A0) )
  {
    v14 = PROTO_CMD_REQ;
  }
  else if ( !(unsigned int)std::string::compare(v3 + 32, &off_19E8C4E0) )
  {
    v14 = PROTO_CMD_RSP;
  }
  else if ( !(unsigned int)std::string::compare(v3 + 32, "Notify") )
  {
    v14 = PROTO_CMD_NOTIFY;
  }
  else
  {
    v14 = PROTO_CMD_NONE;
  }
  v15 = *(std::string::$CFBEC286C7F52157F7E59FC354047095 **)(v3 + 32);
  if ( v15 != (std::string::$CFBEC286C7F52157F7E59FC354047095 *)(v3 + 48) )
    operator delete(v15);
  if ( v17 == (_BYTE *)v3 )
  {
    *(_DWORD *)((v3 >> 3) + 0x7FFF8000) = 0;
    *(_DWORD *)((v3 >> 3) + 0x7FFF8008) = 0;
  }
  else
  {
    *(_QWORD *)v3 = 1172321806LL;
    *(_QWORD *)((v3 >> 3) + 0x7FFF8000) = 0xF5F5F5F5F5F5F5F5LL;
    *(_DWORD *)((v3 >> 3) + 0x7FFF8008) = -168430091;
  }
  return v14;
};

// Line 679: range 000000000C7FD3B6-000000000C7FD75F
void __fastcall ProtoUtils::tamperMessage(MessagePtr message_ptr)
{
  std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *v1; // rax
  std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *v2; // rax
  char v3; // dl
  char v4; // cl
  std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type **v5; // rbx
  char v6; // dl
  signed __int32 v7; // eax
  char v8; // dl
  char v9; // dl
  signed __int32 v10; // eax
  char v11; // dl
  struct _Unwind_Exception *v12; // rbp
  unsigned __int64 v13; // rbx
  char v14; // dl
  signed __int32 i; // eax
  char v16; // dl
  __int64 v17; // rax
  char v18; // dl
  signed __int32 j; // eax
  char v20; // dl
  __int64 v21; // rax
  int (**vptr_MessageLite)(...); // [rsp+0h] [rbp-28h] BYREF
  std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *v23; // [rsp+8h] [rbp-20h]

  if ( *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000) )
  {
    v1 = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)__asan_report_load8(message_ptr._M_ptr);
    goto LABEL_10;
  }
  vptr_MessageLite = message_ptr._M_ptr->_vptr_MessageLite;
  v1 = message_ptr._M_ptr + 1;
  if ( *(_BYTE *)(((unsigned __int64)&message_ptr._M_ptr[1] >> 3) + 0x7FFF8000) )
  {
LABEL_10:
    message_ptr._M_ptr = v1;
    __asan_report_load8(v1);
LABEL_11:
    v2 = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)__asan_report_store4(
                                                                                                    message_ptr._M_ptr,
                                                                                                    message_ptr._M_refcount._M_pi);
    goto LABEL_12;
  }
  v2 = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)message_ptr._M_ptr[1]._vptr_MessageLite;
  v23 = v2;
  if ( !v2 )
  {
LABEL_8:
    message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)&vptr_MessageLite;
    ProtoUtils::TamperUtils::tamperMessage(message_ptr);
    goto LABEL_16;
  }
  message_ptr._M_ptr = v2 + 1;
  if ( &_pthread_key_create )
  {
    v3 = *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000);
    if ( (char)(((__int64)message_ptr._M_ptr & 7) + 3) < v3 || !v3 )
    {
      _InterlockedAdd((volatile signed __int32 *)message_ptr._M_ptr, 1u);
      goto LABEL_8;
    }
    goto LABEL_11;
  }
LABEL_12:
  v4 = *(_BYTE *)(((unsigned __int64)&v2[1] >> 3) + 0x7FFF8000);
  if ( (char)((((_BYTE)v2 + 8) & 7) + 3) < v4 || !v4 )
  {
    ++LODWORD(v2[1]._vptr_MessageLite);
    goto LABEL_8;
  }
  __asan_report_load4(&v2[1]);
LABEL_16:
  v5 = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type **)v23;
  if ( !v23 )
    return;
  message_ptr._M_ptr = v23 + 1;
  if ( &_pthread_key_create )
  {
    v6 = *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000);
    if ( (char)(((__int64)message_ptr._M_ptr & 7) + 3) < v6 || !v6 )
    {
      v7 = _InterlockedExchangeAdd((volatile signed __int32 *)message_ptr._M_ptr, 0xFFFFFFFF);
      goto LABEL_21;
    }
    __asan_report_store4(message_ptr._M_ptr, message_ptr._M_refcount._M_pi);
  }
  v8 = *(_BYTE *)(((unsigned __int64)(v5 + 1) >> 3) + 0x7FFF8000);
  if ( (char)((((_BYTE)v5 + 8) & 7) + 3) >= v8 && v8 )
  {
    __asan_report_load4(v5 + 1);
    goto LABEL_28;
  }
  v7 = *((_DWORD *)v5 + 2);
  *((_DWORD *)v5 + 2) = v7 - 1;
LABEL_21:
  if ( v7 != 1 )
    return;
LABEL_28:
  if ( *(_BYTE *)(((unsigned __int64)v5 >> 3) + 0x7FFF8000) )
  {
    message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)v5;
    __asan_report_load8(v5);
    goto LABEL_39;
  }
  message_ptr._M_ptr = *v5 + 2;
  if ( *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000) )
  {
LABEL_39:
    __asan_report_load8(message_ptr._M_ptr);
    goto LABEL_40;
  }
  ((void (__fastcall *)(std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type **))(*v5)[2]._vptr_MessageLite)(v5);
  message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)((char *)v5 + 12);
  if ( !&_pthread_key_create )
    goto LABEL_41;
  v9 = *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000);
  if ( (char)(((__int64)message_ptr._M_ptr & 7) + 3) < v9 || !v9 )
  {
    v10 = _InterlockedExchangeAdd((volatile signed __int32 *)message_ptr._M_ptr, 0xFFFFFFFF);
    goto LABEL_34;
  }
LABEL_40:
  __asan_report_store4(message_ptr._M_ptr, message_ptr._M_refcount._M_pi);
LABEL_41:
  v11 = *(_BYTE *)((((unsigned __int64)v5 + 12) >> 3) + 0x7FFF8000);
  if ( (char)((((_BYTE)v5 + 12) & 7) + 3) >= v11 && v11 )
  {
    __asan_report_load4((char *)v5 + 12);
    goto LABEL_45;
  }
  v10 = *((_DWORD *)v5 + 3);
  *((_DWORD *)v5 + 3) = v10 - 1;
LABEL_34:
  if ( v10 == 1 )
  {
    if ( !*(_BYTE *)(((unsigned __int64)v5 >> 3) + 0x7FFF8000) )
    {
      message_ptr._M_ptr = *v5 + 3;
      if ( !*(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000) )
      {
        ((void (__fastcall *)(std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type **))(*v5)[3]._vptr_MessageLite)(v5);
        return;
      }
LABEL_46:
      v12 = (struct _Unwind_Exception *)__asan_report_load8(message_ptr._M_ptr);
      v13 = (unsigned __int64)v23;
      if ( v23 )
      {
        message_ptr._M_ptr = v23 + 1;
        if ( !&_pthread_key_create )
          goto LABEL_55;
        v14 = *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000);
        if ( (char)(((__int64)message_ptr._M_ptr & 7) + 3) >= v14 && v14 )
          __asan_report_store4(message_ptr._M_ptr, message_ptr._M_refcount._M_pi);
        for ( i = _InterlockedExchangeAdd((volatile signed __int32 *)message_ptr._M_ptr, 0xFFFFFFFF);
              ;
              *(_DWORD *)(v13 + 8) = i - 1 )
        {
          if ( i != 1 )
            goto LABEL_76;
          if ( !*(_BYTE *)((v13 >> 3) + 0x7FFF8000) )
            break;
          __asan_report_load8(v13);
LABEL_55:
          message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)(v13 + 8);
          v16 = *(_BYTE *)(((v13 + 8) >> 3) + 0x7FFF8000);
          if ( (char)(((v13 + 8) & 7) + 3) >= v16 )
          {
            if ( v16 )
              __asan_report_load4(message_ptr._M_ptr);
          }
          i = *(_DWORD *)(v13 + 8);
        }
        v17 = *(_QWORD *)v13;
        if ( *(_BYTE *)(((unsigned __int64)(*(_QWORD *)v13 + 16LL) >> 3) + 0x7FFF8000) )
          v17 = __asan_report_load8(*(_QWORD *)v13 + 16LL);
        (*(void (__fastcall **)(unsigned __int64))(v17 + 16))(v13);
        message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)(v13 + 12);
        if ( !&_pthread_key_create )
          goto LABEL_69;
        v18 = *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000);
        if ( (char)(((__int64)message_ptr._M_ptr & 7) + 3) >= v18 && v18 )
          __asan_report_store4(message_ptr._M_ptr, message_ptr._M_refcount._M_pi);
        for ( j = _InterlockedExchangeAdd((volatile signed __int32 *)message_ptr._M_ptr, 0xFFFFFFFF);
              ;
              *(_DWORD *)(v13 + 12) = j - 1 )
        {
          if ( j != 1 )
            goto LABEL_76;
          if ( !*(_BYTE *)((v13 >> 3) + 0x7FFF8000) )
            break;
          __asan_report_load8(v13);
LABEL_69:
          message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)(v13 + 12);
          v20 = *(_BYTE *)(((v13 + 12) >> 3) + 0x7FFF8000);
          if ( (char)(((v13 + 12) & 7) + 3) >= v20 && v20 )
            __asan_report_load4(message_ptr._M_ptr);
          j = *(_DWORD *)(v13 + 12);
        }
        v21 = *(_QWORD *)v13;
        if ( *(_BYTE *)(((unsigned __int64)(*(_QWORD *)v13 + 24LL) >> 3) + 0x7FFF8000) )
          v21 = __asan_report_load8(*(_QWORD *)v13 + 24LL);
        message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)v13;
        (*(void (__fastcall **)(unsigned __int64))(v21 + 24))(v13);
      }
LABEL_76:
      __asan_handle_no_return(message_ptr._M_ptr);
      _Unwind_Resume(v12);
    }
LABEL_45:
    message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)v5;
    __asan_report_load8(v5);
    goto LABEL_46;
  }
};

// Line 749: range 000000000C7FD28A-000000000C7FD3B0
void __fastcall ProtoUtils::TamperUtils::tamperMessage(MessagePtr message_ptr)
{
  google::protobuf::Message **M_ptr; // rbx
  unsigned __int64 v2; // rdx
  unsigned __int64 v3; // rax
  struct _Unwind_Exception *v4; // rbx
  common::milog::MiLogStream v5; // [rsp+0h] [rbp-38h] BYREF

  M_ptr = (google::protobuf::Message **)message_ptr._M_ptr;
  if ( *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000) )
  {
    __asan_report_load8(message_ptr._M_ptr);
    goto LABEL_9;
  }
  message_ptr._M_ptr = (std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *)message_ptr._M_ptr->_vptr_MessageLite;
  if ( !message_ptr._M_ptr )
  {
LABEL_9:
    common::milog::MiLogStream::MiLogStream(
      &v5,
      &common::milog::MiLogDefault::default_log_obj_,
      4u,
      "src/proto_utils.cpp",
      "tamperMessage",
      752);
    common::milog::MiLogStream::operator()(&v5, "message_ptr == nullptr");
    common::milog::MiLogStream::~MiLogStream(&v5);
    return;
  }
  if ( *(_BYTE *)(((unsigned __int64)message_ptr._M_ptr >> 3) + 0x7FFF8000) )
  {
    __asan_report_load8(message_ptr._M_ptr);
    goto LABEL_11;
  }
  v2 = (unsigned __int64)(message_ptr._M_ptr->_vptr_MessageLite + 24);
  if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
  {
LABEL_11:
    v3 = __asan_report_load8(v2);
    goto LABEL_12;
  }
  v3 = (*((__int64 (__fastcall **)(std::__shared_ptr<google::protobuf::Message,(__gnu_cxx::_Lock_policy)2>::element_type *, std::_Sp_counted_base<(__gnu_cxx::_Lock_policy)2> *))message_ptr._M_ptr->_vptr_MessageLite
        + 24))(
         message_ptr._M_ptr,
         message_ptr._M_refcount._M_pi);
  if ( !*(_BYTE *)((v3 >> 3) + 0x7FFF8000) )
  {
    if ( &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header != (std::_Rb_tree_header *)std::_Rb_tree<std::string,std::string,std::_Identity<std::string>,std::less<std::string>,std::allocator<std::string>>::find(&ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t, *(const std::string **)v3)._M_node )
      return;
    goto LABEL_13;
  }
LABEL_12:
  __asan_report_load8(v3);
LABEL_13:
  if ( *(_BYTE *)(((unsigned __int64)M_ptr >> 3) + 0x7FFF8000) )
  {
    v4 = (struct _Unwind_Exception *)__asan_report_load8(M_ptr);
    common::milog::MiLogStream::~MiLogStream(&v5);
    __asan_handle_no_return(&v5);
    _Unwind_Resume(v4);
  }
  ProtoUtils::TamperUtils::doTamperMessage(*M_ptr);
};

// Line 766: range 000000000C7FAE44-000000000C7FC05A
void __fastcall ProtoUtils::TamperUtils::doTamperMessage(google::protobuf::Message *message_ptr)
{
  __int64 v1; // rbp
  unsigned __int64 v2; // r12
  google::protobuf::Message *v3; // r13
  int v4; // r15d
  google::protobuf::Message *v5; // rbx
  int (**vptr_MessageLite)(...); // rax
  char v7; // al
  int v8; // eax
  google::protobuf::Message *v9; // rdi
  char v10; // dl
  char v11; // dl
  unsigned __int64 v12; // rdi
  void (__fastcall *v13)(unsigned __int64, google::protobuf::Message *, __int64, double); // r13
  char v14; // dl
  unsigned __int64 v15; // rdi
  int v16; // eax
  unsigned __int64 v17; // rcx
  char v18; // dl
  unsigned __int64 p_M_finish; // rdi
  void (__fastcall *v20)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, _QWORD); // r14
  int v21; // eax
  unsigned __int64 v22; // rcx
  char v23; // dl
  unsigned int v24; // r15d
  int v25; // eax
  char v26; // dl
  unsigned __int64 v27; // rdi
  int v28; // eax
  unsigned __int64 v29; // rdi
  void (__fastcall *v30)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, double); // r14
  int v31; // eax
  char v32; // dl
  int v33; // eax
  unsigned __int64 v34; // rcx
  char v35; // dl
  int v36; // eax
  unsigned __int64 v37; // rcx
  char v38; // dl
  char v39; // dl
  int v40; // eax
  int v41; // eax
  char v42; // dl
  int v43; // eax
  int v44; // eax
  double v45; // r15
  int v46; // eax
  char v47; // dl
  unsigned __int64 v48; // rdi
  int v49; // eax
  unsigned __int64 v50; // rcx
  char v51; // dl
  unsigned __int64 v52; // rdi
  void (__fastcall *v53)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, double); // r14
  int v54; // eax
  unsigned __int64 v55; // rcx
  char v56; // dl
  unsigned int v57; // r15d
  int v58; // eax
  char v59; // dl
  unsigned __int64 v60; // rdi
  void (__fastcall *v61)(unsigned __int64, google::protobuf::Message *, __int64, bool); // r13
  char v62; // al
  unsigned __int64 v63; // rdi
  void (__fastcall *v64)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, _QWORD); // r15
  int v65; // r14d
  int v66; // eax
  __int64 v67; // r14
  __int64 v68; // rdi
  char v69; // dl
  char v70; // dl
  unsigned __int64 v71; // rdi
  int v72; // edx
  unsigned __int64 v73; // rdi
  int v74; // edx
  __int64 v75; // r14
  __int64 v76; // rcx
  char v77; // dl
  unsigned __int64 v78; // rdi
  google::protobuf::Message *v79; // rax
  unsigned __int64 v80; // rdi
  __int64 (__fastcall *v81)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD); // r14
  int v82; // eax
  google::protobuf::Message *v83; // rax
  int v84; // eax
  void (__fastcall *v85)(unsigned __int64, google::protobuf::Message *, __int64, __int64, __int64); // [rsp+8h] [rbp-60h]
  common::milog::MiLogStream v86; // [rsp+10h] [rbp-58h] BYREF

  v5 = message_ptr;
  if ( *(_BYTE *)(((unsigned __int64)message_ptr >> 3) + 0x7FFF8000) )
  {
    __asan_report_load8(message_ptr);
    goto LABEL_9;
  }
  vptr_MessageLite = message_ptr->_vptr_MessageLite;
  message_ptr = (google::protobuf::Message *)(message_ptr->_vptr_MessageLite + 24);
  if ( *(_BYTE *)(((unsigned __int64)message_ptr >> 3) + 0x7FFF8000) )
  {
LABEL_9:
    __asan_report_load8(message_ptr);
    goto LABEL_10;
  }
  v3 = (google::protobuf::Message *)((__int64 (__fastcall *)(google::protobuf::Message *))vptr_MessageLite[24])(v5);
  message_ptr = (google::protobuf::Message *)(v5->_vptr_MessageLite + 23);
  if ( *(_BYTE *)(((unsigned __int64)message_ptr >> 3) + 0x7FFF8000) )
  {
LABEL_10:
    __asan_report_load8(message_ptr);
LABEL_11:
    __asan_report_load4(message_ptr);
    goto LABEL_12;
  }
  v2 = (*((__int64 (__fastcall **)(google::protobuf::Message *))v5->_vptr_MessageLite + 23))(v5);
  message_ptr = v3 + 13;
  v7 = *(_BYTE *)(((unsigned __int64)&v3[13] >> 3) + 0x7FFF8000);
  if ( v7 && v7 <= 3 )
    goto LABEL_11;
  if ( !LODWORD(v3[13]._vptr_MessageLite) )
    return;
LABEL_12:
  v8 = rand();
  v9 = v3 + 13;
  v10 = *(_BYTE *)(((unsigned __int64)&v3[13] >> 3) + 0x7FFF8000);
  if ( v10 && v10 <= 3 )
  {
    __asan_report_load4(v9);
    goto LABEL_23;
  }
  v9 = v3 + 5;
  if ( *(_BYTE *)(((unsigned __int64)&v3[5] >> 3) + 0x7FFF8000) )
  {
LABEL_23:
    __asan_report_load8(v9);
LABEL_24:
    __asan_report_load4(v9);
    goto LABEL_25;
  }
  v1 = (__int64)&v3[5]._vptr_MessageLite[19 * (v8 % SLODWORD(v3[13]._vptr_MessageLite))];
  v9 = (google::protobuf::Message *)(v1 + 60);
  v11 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
  if ( (char)(((LOBYTE(v3[5]._vptr_MessageLite) - 104 * (v8 % SLODWORD(v3[13]._vptr_MessageLite)) + 60) & 7) + 3) >= v11
    && v11 )
  {
    goto LABEL_24;
  }
  if ( *(_DWORD *)(v1 + 60) == 3 )
  {
    if ( !*(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
    {
      v12 = *(_QWORD *)v2 + 48LL;
      if ( !*(_BYTE *)((v12 >> 3) + 0x7FFF8000) )
      {
        LODWORD(v13) = (*(__int64 (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64))(*(_QWORD *)v2 + 48LL))(
                         v2,
                         v5,
                         v1);
        if ( !(_DWORD)v13 )
          return;
        goto LABEL_28;
      }
      goto LABEL_26;
    }
LABEL_25:
    v12 = v2;
    __asan_report_load8(v2);
LABEL_26:
    __asan_report_load8(v12);
  }
  LODWORD(v13) = 0;
LABEL_28:
  switch ( (unsigned int)google::protobuf::FieldDescriptor::type((google::protobuf::FieldDescriptor *)v1) )
  {
    case 1u:
      goto LABEL_137;
    case 2u:
      goto LABEL_163;
    case 3u:
    case 0x10u:
    case 0x12u:
      goto LABEL_57;
    case 4u:
    case 6u:
      goto LABEL_111;
    case 5u:
    case 0xFu:
    case 0x11u:
      v14 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v14 && v14 )
      {
        __asan_report_load4(v1 + 60);
LABEL_40:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          p_M_finish = v2;
          __asan_report_load8(v2);
        }
        else
        {
          p_M_finish = *(_QWORD *)v2 + 432LL;
          if ( !*(_BYTE *)((p_M_finish >> 3) + 0x7FFF8000) )
          {
            v20 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, _QWORD))(*(_QWORD *)v2 + 432LL);
            v21 = rand();
            p_M_finish = (unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish;
            if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish >> 3)
                           + 0x7FFF8000) )
            {
              p_M_finish = (unsigned __int64)&ProtoUtils::TamperUtils::int32Vector;
              if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector >> 3) + 0x7FFF8000) )
              {
                v22 = ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish
                    - ProtoUtils::TamperUtils::int32Vector._M_impl._M_start;
                p_M_finish = (unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_start[v21 % v22];
                v23 = *(_BYTE *)((p_M_finish >> 3) + 0x7FFF8000);
                if ( (char)(((LOBYTE(ProtoUtils::TamperUtils::int32Vector._M_impl._M_start) + 4 * (v21 % v22)) & 7) + 3) < v23
                  || !v23 )
                {
                  goto LABEL_46;
                }
                goto LABEL_51;
              }
LABEL_50:
              __asan_report_load8(p_M_finish);
LABEL_51:
              __asan_report_load4(p_M_finish);
              goto LABEL_52;
            }
LABEL_49:
            __asan_report_load8(p_M_finish);
            goto LABEL_50;
          }
        }
        __asan_report_load8(p_M_finish);
        goto LABEL_49;
      }
      if ( *(_DWORD *)(v1 + 60) == 3 )
        goto LABEL_40;
      if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
LABEL_52:
        v15 = v2;
        __asan_report_load8(v2);
        goto LABEL_53;
      }
      v15 = *(_QWORD *)v2 + 232LL;
      if ( *(_BYTE *)((v15 >> 3) + 0x7FFF8000) )
      {
LABEL_53:
        __asan_report_load8(v15);
        goto LABEL_54;
      }
      v13 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, double))(*(_QWORD *)v2 + 232LL);
      v16 = rand();
      v15 = (unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
      {
LABEL_54:
        __asan_report_load8(v15);
        goto LABEL_55;
      }
      v15 = (unsigned __int64)&ProtoUtils::TamperUtils::int32Vector;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector >> 3) + 0x7FFF8000) )
      {
LABEL_55:
        __asan_report_load8(v15);
        goto LABEL_56;
      }
      v17 = ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish
          - ProtoUtils::TamperUtils::int32Vector._M_impl._M_start;
      v15 = (unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_start[v16 % v17];
      v18 = *(_BYTE *)((v15 >> 3) + 0x7FFF8000);
      if ( (char)(((LOBYTE(ProtoUtils::TamperUtils::int32Vector._M_impl._M_start) + 4 * (v16 % v17)) & 7) + 3) < v18
        || !v18 )
      {
        goto LABEL_38;
      }
LABEL_56:
      __asan_report_load4(v15);
LABEL_57:
      v26 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v26 && v26 )
      {
        __asan_report_load4(v1 + 60);
LABEL_67:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          v29 = v2;
          __asan_report_load8(v2);
        }
        else
        {
          v29 = *(_QWORD *)v2 + 440LL;
          if ( !*(_BYTE *)((v29 >> 3) + 0x7FFF8000) )
          {
            v30 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, double))(*(_QWORD *)v2 + 440LL);
            v31 = rand();
            v29 = (unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish;
            if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish >> 3)
                           + 0x7FFF8000) )
            {
              v29 = (unsigned __int64)&ProtoUtils::TamperUtils::int64Vector;
              if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector >> 3) + 0x7FFF8000) )
              {
                v29 = (unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_start[v31
                                                                                             % (unsigned __int64)(ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish - ProtoUtils::TamperUtils::int64Vector._M_impl._M_start)];
                if ( !*(_BYTE *)((v29 >> 3) + 0x7FFF8000) )
                  goto LABEL_152;
                goto LABEL_77;
              }
LABEL_76:
              __asan_report_load8(v29);
LABEL_77:
              __asan_report_load8(v29);
              goto LABEL_78;
            }
LABEL_75:
            __asan_report_load8(v29);
            goto LABEL_76;
          }
        }
        __asan_report_load8(v29);
        goto LABEL_75;
      }
      if ( *(_DWORD *)(v1 + 60) == 3 )
        goto LABEL_67;
      if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
LABEL_78:
        v27 = v2;
        __asan_report_load8(v2);
        goto LABEL_79;
      }
      v27 = *(_QWORD *)v2 + 240LL;
      if ( *(_BYTE *)((v27 >> 3) + 0x7FFF8000) )
      {
LABEL_79:
        __asan_report_load8(v27);
        goto LABEL_80;
      }
      v13 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, double))(*(_QWORD *)v2 + 240LL);
      v28 = rand();
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
      {
LABEL_80:
        __asan_report_load8(v27);
        goto LABEL_81;
      }
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::int64Vector;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector >> 3) + 0x7FFF8000) )
      {
LABEL_81:
        __asan_report_load8(v27);
        goto LABEL_82;
      }
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_start[v28
                                                                                   % (unsigned __int64)(ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish - ProtoUtils::TamperUtils::int64Vector._M_impl._M_start)];
      if ( !*(_BYTE *)((v27 >> 3) + 0x7FFF8000) )
        goto LABEL_145;
LABEL_82:
      __asan_report_load8(v27);
LABEL_83:
      v32 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v32 && v32 )
      {
        __asan_report_load4(v1 + 60);
LABEL_94:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          p_M_finish = v2;
          __asan_report_load8(v2);
        }
        else
        {
          p_M_finish = *(_QWORD *)v2 + 448LL;
          if ( !*(_BYTE *)((p_M_finish >> 3) + 0x7FFF8000) )
          {
            v20 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, _QWORD))(*(_QWORD *)v2 + 448LL);
            v36 = rand();
            p_M_finish = (unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish;
            if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish >> 3)
                           + 0x7FFF8000) )
            {
              p_M_finish = (unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector;
              if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector >> 3) + 0x7FFF8000) )
              {
                v37 = ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish
                    - ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start;
                p_M_finish = (unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start[v36 % v37];
                v38 = *(_BYTE *)((p_M_finish >> 3) + 0x7FFF8000);
                if ( (char)(((LOBYTE(ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start) + 4 * (v36 % v37)) & 7) + 3) < v38
                  || !v38 )
                {
LABEL_46:
                  v24 = *(_DWORD *)p_M_finish;
                  v25 = rand();
                  v20(v2, v5, v1, (unsigned int)(v25 % (int)v13), v24);
                  return;
                }
LABEL_105:
                __asan_report_load4(p_M_finish);
                goto LABEL_106;
              }
LABEL_104:
              __asan_report_load8(p_M_finish);
              goto LABEL_105;
            }
LABEL_103:
            __asan_report_load8(p_M_finish);
            goto LABEL_104;
          }
        }
        __asan_report_load8(p_M_finish);
        goto LABEL_103;
      }
      if ( *(_DWORD *)(v1 + 60) == 3 )
        goto LABEL_94;
      if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
LABEL_106:
        v15 = v2;
        __asan_report_load8(v2);
        goto LABEL_107;
      }
      v15 = *(_QWORD *)v2 + 248LL;
      if ( *(_BYTE *)((v15 >> 3) + 0x7FFF8000) )
      {
LABEL_107:
        __asan_report_load8(v15);
        goto LABEL_108;
      }
      v13 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, double))(*(_QWORD *)v2 + 248LL);
      v33 = rand();
      v15 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
      {
LABEL_108:
        __asan_report_load8(v15);
        goto LABEL_109;
      }
      v15 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector >> 3) + 0x7FFF8000) )
      {
LABEL_109:
        __asan_report_load8(v15);
        goto LABEL_110;
      }
      v34 = ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish
          - ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start;
      v15 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start[v33 % v34];
      v35 = *(_BYTE *)((v15 >> 3) + 0x7FFF8000);
      if ( (char)(((LOBYTE(ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start) + 4 * (v33 % v34)) & 7) + 3) < v35
        || !v35 )
      {
LABEL_38:
        ((void (__fastcall *)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD))v13)(
          v2,
          v5,
          v1,
          *(unsigned int *)v15);
        return;
      }
LABEL_110:
      __asan_report_load4(v15);
LABEL_111:
      v39 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v39 && v39 )
      {
        __asan_report_load4(v1 + 60);
LABEL_121:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          v29 = v2;
          __asan_report_load8(v2);
        }
        else
        {
          v29 = *(_QWORD *)v2 + 456LL;
          if ( !*(_BYTE *)((v29 >> 3) + 0x7FFF8000) )
          {
            v30 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, double))(*(_QWORD *)v2 + 456LL);
            v41 = rand();
            v29 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish;
            if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish >> 3)
                           + 0x7FFF8000) )
            {
              v29 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector;
              if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector >> 3) + 0x7FFF8000) )
              {
                v29 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start[v41
                                                                                              % (unsigned __int64)(ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish - ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start)];
                if ( !*(_BYTE *)((v29 >> 3) + 0x7FFF8000) )
                  goto LABEL_152;
                goto LABEL_131;
              }
LABEL_130:
              __asan_report_load8(v29);
LABEL_131:
              __asan_report_load8(v29);
              goto LABEL_132;
            }
LABEL_129:
            __asan_report_load8(v29);
            goto LABEL_130;
          }
        }
        __asan_report_load8(v29);
        goto LABEL_129;
      }
      if ( *(_DWORD *)(v1 + 60) == 3 )
        goto LABEL_121;
      if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
LABEL_132:
        v27 = v2;
        __asan_report_load8(v2);
        goto LABEL_133;
      }
      v27 = *(_QWORD *)v2 + 256LL;
      if ( *(_BYTE *)((v27 >> 3) + 0x7FFF8000) )
      {
LABEL_133:
        __asan_report_load8(v27);
        goto LABEL_134;
      }
      v13 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, double))(*(_QWORD *)v2 + 256LL);
      v40 = rand();
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
      {
LABEL_134:
        __asan_report_load8(v27);
        goto LABEL_135;
      }
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector >> 3) + 0x7FFF8000) )
      {
LABEL_135:
        __asan_report_load8(v27);
        goto LABEL_136;
      }
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start[v40
                                                                                    % (unsigned __int64)(ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish - ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start)];
      if ( !*(_BYTE *)((v27 >> 3) + 0x7FFF8000) )
        goto LABEL_145;
LABEL_136:
      __asan_report_load8(v27);
LABEL_137:
      v42 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v42 && v42 )
      {
        __asan_report_load4(v1 + 60);
LABEL_147:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          v29 = v2;
          __asan_report_load8(v2);
        }
        else
        {
          v29 = *(_QWORD *)v2 + 472LL;
          if ( !*(_BYTE *)((v29 >> 3) + 0x7FFF8000) )
          {
            v30 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, double))(*(_QWORD *)v2 + 472LL);
            v44 = rand();
            v29 = (unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish;
            if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish >> 3)
                           + 0x7FFF8000) )
            {
              v29 = (unsigned __int64)&ProtoUtils::TamperUtils::doubleVector;
              if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector >> 3) + 0x7FFF8000) )
              {
                v29 = (unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_start[v44
                                                                                              % (unsigned __int64)(ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish - ProtoUtils::TamperUtils::doubleVector._M_impl._M_start)];
                if ( !*(_BYTE *)((v29 >> 3) + 0x7FFF8000) )
                {
LABEL_152:
                  v45 = *(double *)v29;
                  v46 = rand();
                  v30(v2, v5, v1, (unsigned int)(v46 % (int)v13), v45);
                  return;
                }
LABEL_157:
                __asan_report_load8(v29);
                goto LABEL_158;
              }
LABEL_156:
              __asan_report_load8(v29);
              goto LABEL_157;
            }
LABEL_155:
            __asan_report_load8(v29);
            goto LABEL_156;
          }
        }
        __asan_report_load8(v29);
        goto LABEL_155;
      }
      if ( *(_DWORD *)(v1 + 60) == 3 )
        goto LABEL_147;
      if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
LABEL_158:
        v27 = v2;
        __asan_report_load8(v2);
        goto LABEL_159;
      }
      v27 = *(_QWORD *)v2 + 272LL;
      if ( *(_BYTE *)((v27 >> 3) + 0x7FFF8000) )
      {
LABEL_159:
        __asan_report_load8(v27);
        goto LABEL_160;
      }
      v13 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, double))(*(_QWORD *)v2 + 272LL);
      v43 = rand();
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish >> 3) + 0x7FFF8000) )
      {
LABEL_160:
        __asan_report_load8(v27);
        goto LABEL_161;
      }
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::doubleVector;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector >> 3) + 0x7FFF8000) )
      {
LABEL_161:
        __asan_report_load8(v27);
        goto LABEL_162;
      }
      v27 = (unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_start[v43
                                                                                    % (unsigned __int64)(ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish - ProtoUtils::TamperUtils::doubleVector._M_impl._M_start)];
      if ( !*(_BYTE *)((v27 >> 3) + 0x7FFF8000) )
      {
LABEL_145:
        v13(v2, v5, v1, *(double *)v27);
        return;
      }
LABEL_162:
      __asan_report_load8(v27);
LABEL_163:
      v47 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v47 && v47 )
      {
        __asan_report_load4(v1 + 60);
LABEL_174:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          v52 = v2;
          __asan_report_load8(v2);
        }
        else
        {
          v52 = *(_QWORD *)v2 + 464LL;
          if ( !*(_BYTE *)((v52 >> 3) + 0x7FFF8000) )
          {
            v53 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, double))(*(_QWORD *)v2 + 464LL);
            v54 = rand();
            v52 = (unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_finish;
            if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_finish >> 3)
                           + 0x7FFF8000) )
            {
              v52 = (unsigned __int64)&ProtoUtils::TamperUtils::floatVector;
              if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector >> 3) + 0x7FFF8000) )
              {
                v55 = ProtoUtils::TamperUtils::floatVector._M_impl._M_finish
                    - ProtoUtils::TamperUtils::floatVector._M_impl._M_start;
                v52 = (unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_start[v54 % v55];
                v56 = *(_BYTE *)((v52 >> 3) + 0x7FFF8000);
                if ( (char)(((LOBYTE(ProtoUtils::TamperUtils::floatVector._M_impl._M_start) + 4 * (v54 % v55)) & 7) + 3) < v56
                  || !v56 )
                {
                  v57 = *(_DWORD *)v52;
                  v58 = rand();
                  v53(v2, v5, v1, (unsigned int)(v58 % (int)v13), *(double *)_mm_cvtsi32_si128(v57).m128i_i64);
                  return;
                }
                goto LABEL_185;
              }
LABEL_184:
              __asan_report_load8(v52);
LABEL_185:
              __asan_report_load4(v52);
              goto LABEL_186;
            }
LABEL_183:
            __asan_report_load8(v52);
            goto LABEL_184;
          }
        }
        __asan_report_load8(v52);
        goto LABEL_183;
      }
      if ( *(_DWORD *)(v1 + 60) == 3 )
        goto LABEL_174;
      if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
LABEL_186:
        v48 = v2;
        __asan_report_load8(v2);
        goto LABEL_187;
      }
      v48 = *(_QWORD *)v2 + 264LL;
      if ( *(_BYTE *)((v48 >> 3) + 0x7FFF8000) )
      {
LABEL_187:
        __asan_report_load8(v48);
        goto LABEL_188;
      }
      v13 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, double))(*(_QWORD *)v2 + 264LL);
      v49 = rand();
      v48 = (unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_finish;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_finish >> 3) + 0x7FFF8000) )
      {
LABEL_188:
        __asan_report_load8(v48);
        goto LABEL_189;
      }
      v48 = (unsigned __int64)&ProtoUtils::TamperUtils::floatVector;
      if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector >> 3) + 0x7FFF8000) )
      {
LABEL_189:
        __asan_report_load8(v48);
        goto LABEL_190;
      }
      v50 = ProtoUtils::TamperUtils::floatVector._M_impl._M_finish
          - ProtoUtils::TamperUtils::floatVector._M_impl._M_start;
      v48 = (unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_start[v49 % v50];
      v51 = *(_BYTE *)((v48 >> 3) + 0x7FFF8000);
      if ( (char)(((LOBYTE(ProtoUtils::TamperUtils::floatVector._M_impl._M_start) + 4 * (v49 % v50)) & 7) + 3) < v51
        || !v51 )
      {
        v13(v2, v5, v1, *(float *)v48);
        return;
      }
LABEL_190:
      __asan_report_load4(v48);
LABEL_191:
      v59 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v59 && v59 )
      {
        __asan_report_load4(v1 + 60);
        goto LABEL_198;
      }
      if ( *(_DWORD *)(v1 + 60) == 3 )
      {
LABEL_198:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          v63 = v2;
          __asan_report_load8(v2);
        }
        else
        {
          v63 = *(_QWORD *)v2 + 480LL;
          if ( !*(_BYTE *)((v63 >> 3) + 0x7FFF8000) )
          {
            v64 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD, _QWORD))(*(_QWORD *)v2 + 480LL);
            v65 = rand() & 1;
            v66 = rand();
            v64(v2, v5, v1, (unsigned int)(v66 % (int)v13), v65 ^ 1u);
            return;
          }
        }
        __asan_report_load8(v63);
        goto LABEL_203;
      }
      if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
LABEL_203:
        v60 = v2;
        __asan_report_load8(v2);
        goto LABEL_204;
      }
      v60 = *(_QWORD *)v2 + 280LL;
      if ( !*(_BYTE *)((v60 >> 3) + 0x7FFF8000) )
      {
        v61 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, bool))(*(_QWORD *)v2 + 280LL);
        v62 = rand();
        v61(v2, v5, v1, (v62 & 1) == 0);
        return;
      }
LABEL_204:
      __asan_report_load8(v60);
LABEL_205:
      v67 = google::protobuf::FieldDescriptor::enum_type((google::protobuf::FieldDescriptor *)v1);
      v68 = v67 + 44;
      v69 = *(_BYTE *)(((unsigned __int64)(v67 + 44) >> 3) + 0x7FFF8000);
      if ( (char)(((v67 + 44) & 7) + 3) >= v69 && v69 )
      {
        __asan_report_load4(v68);
LABEL_215:
        __asan_report_load4(v68);
LABEL_216:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          v73 = v2;
          __asan_report_load8(v2);
        }
        else
        {
          v73 = *(_QWORD *)v2 + 496LL;
          if ( !*(_BYTE *)((v73 >> 3) + 0x7FFF8000) )
          {
            v85 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, __int64, __int64))(*(_QWORD *)v2 + 496LL);
            v74 = rand() % v4;
            v73 = v67 + 48;
            if ( !*(_BYTE *)(((unsigned __int64)(v67 + 48) >> 3) + 0x7FFF8000) )
            {
              v75 = *(_QWORD *)(v67 + 48) + 40LL * v74;
              v76 = (unsigned int)(rand() % (int)v13);
              v85(v2, v5, v1, v76, v75);
              return;
            }
            goto LABEL_222;
          }
        }
        __asan_report_load8(v73);
LABEL_222:
        __asan_report_load8(v73);
        goto LABEL_223;
      }
      v4 = *(_DWORD *)(v67 + 44);
      v68 = v1 + 60;
      v70 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v70 && v70 )
        goto LABEL_215;
      if ( *(_DWORD *)(v1 + 60) == 3 )
        goto LABEL_216;
      if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
LABEL_223:
        v71 = v2;
        __asan_report_load8(v2);
        goto LABEL_224;
      }
      v71 = *(_QWORD *)v2 + 296LL;
      if ( *(_BYTE *)((v71 >> 3) + 0x7FFF8000) )
      {
LABEL_224:
        __asan_report_load8(v71);
        goto LABEL_225;
      }
      v13 = *(void (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, double))(*(_QWORD *)v2 + 296LL);
      v72 = rand() % v4;
      v71 = v67 + 48;
      if ( !*(_BYTE *)(((unsigned __int64)(v67 + 48) >> 3) + 0x7FFF8000) )
      {
        ((void (__fastcall *)(unsigned __int64, google::protobuf::Message *, __int64, __int64))v13)(
          v2,
          v5,
          v1,
          *(_QWORD *)(v67 + 48) + 40LL * v72);
        return;
      }
LABEL_225:
      __asan_report_load8(v71);
LABEL_226:
      v77 = *(_BYTE *)(((unsigned __int64)(v1 + 60) >> 3) + 0x7FFF8000);
      if ( (char)(((v1 + 60) & 7) + 3) >= v77 && v77 )
      {
        __asan_report_load4(v1 + 60);
        goto LABEL_233;
      }
      if ( *(_DWORD *)(v1 + 60) == 3 )
      {
LABEL_233:
        if ( *(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
        {
          v80 = v2;
          __asan_report_load8(v2);
        }
        else
        {
          v80 = *(_QWORD *)v2 + 512LL;
          if ( !*(_BYTE *)((v80 >> 3) + 0x7FFF8000) )
          {
            v81 = *(__int64 (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD))(*(_QWORD *)v2 + 512LL);
            v82 = rand();
            v83 = (google::protobuf::Message *)v81(v2, v5, v1, (unsigned int)(v82 % (int)v13));
            ProtoUtils::TamperUtils::doTamperMessage(v83);
            return;
          }
        }
        __asan_report_load8(v80);
        goto LABEL_238;
      }
      if ( !*(_BYTE *)((v2 >> 3) + 0x7FFF8000) )
      {
        v78 = *(_QWORD *)v2 + 312LL;
        if ( !*(_BYTE *)((v78 >> 3) + 0x7FFF8000) )
        {
          v79 = (google::protobuf::Message *)(*(__int64 (__fastcall **)(unsigned __int64, google::protobuf::Message *, __int64, _QWORD))(*(_QWORD *)v2 + 312LL))(
                                               v2,
                                               v5,
                                               v1,
                                               0LL);
          ProtoUtils::TamperUtils::doTamperMessage(v79);
          return;
        }
        goto LABEL_239;
      }
LABEL_238:
      v78 = v2;
      __asan_report_load8(v2);
LABEL_239:
      __asan_report_load8(v78);
LABEL_240:
      common::milog::MiLogStream::MiLogStream(
        &v86,
        &common::milog::MiLogDefault::default_log_obj_,
        4u,
        "src/proto_utils.cpp",
        "doTamperMessage",
        922);
      v84 = google::protobuf::FieldDescriptor::type((google::protobuf::FieldDescriptor *)v1);
      if ( *(_BYTE *)(((unsigned __int64)&google::protobuf::FieldDescriptor::kTypeToName[v84] >> 3) + 0x7FFF8000) )
        __asan_report_load8(&google::protobuf::FieldDescriptor::kTypeToName[v84]);
      else
        common::milog::MiLogStream::operator()(
          &v86,
          "invalid type:%s\n",
          google::protobuf::FieldDescriptor::kTypeToName[v84]);
      common::milog::MiLogStream::~MiLogStream(&v86);
      return;
    case 7u:
    case 0xDu:
      goto LABEL_83;
    case 8u:
      goto LABEL_191;
    case 9u:
    case 0xCu:
      return;
    case 0xAu:
    case 0xBu:
      goto LABEL_226;
    case 0xEu:
      goto LABEL_205;
    default:
      goto LABEL_240;
  }
};

// Line 924: range 000000000C801E98-000000000C801EAF
void __cdecl GLOBAL__sub_I_proto_utils_cpp()
{
  __static_initialization_and_destruction_0(1, 0xFFFF);
};

// Line 924: range 000000000C80032A-000000000C801E93
void __fastcall __static_initialization_and_destruction_0(int __initialize_p, int __priority)
{
  unsigned __int64 v2; // rbx
  int *v3; // r15
  unsigned __int64 v4; // rbp
  __int64 v5; // rax
  const std::string *p_a; // r12
  std::set<unsigned int> *v7; // rsi
  void *p_M_parent; // rdi
  char v9; // al
  char v10; // al
  char v11; // al
  char v12; // al
  char v13; // al
  char v14; // al
  char v15; // al
  char v16; // al
  char v17; // al
  char v18; // al
  char v19; // al
  std::string *v20; // r12
  std::string::pointer M_p; // rdi
  __int64 *p_src; // rsi
  std::vector<int> *p_M_finish; // rdi
  int *v24; // rax
  int *v25; // rdi
  int *v26; // r13
  std::_Vector_base<int>::pointer *p_M_end_of_storage; // rax
  std::_Vector_base<int>::pointer *v28; // rdi
  std::vector<long int> *v29; // rdi
  __int64 *v30; // rax
  struct _Unwind_Exception *v31; // rbx
  std::_Vector_base<int>::pointer M_start; // rdi
  __int64 *v33; // rdi
  __int64 *v34; // r13
  std::_Vector_base<long int>::pointer *v35; // rax
  std::_Vector_base<long int>::pointer *v36; // rdi
  std::vector<unsigned int> *v37; // rdi
  unsigned int *v38; // rax
  struct _Unwind_Exception *v39; // rbx
  std::_Vector_base<long int>::pointer v40; // rdi
  unsigned int *v41; // rdi
  unsigned int *v42; // r13
  std::_Vector_base<unsigned int>::pointer *v43; // rax
  std::_Vector_base<unsigned int>::pointer *v44; // rdi
  std::vector<long unsigned int> *v45; // rdi
  unsigned __int64 *v46; // rax
  struct _Unwind_Exception *v47; // rbx
  std::_Vector_base<unsigned int>::pointer v48; // rdi
  unsigned __int64 *v49; // rdi
  unsigned __int64 *v50; // r13
  std::_Vector_base<long unsigned int>::pointer *v51; // rax
  std::_Vector_base<long unsigned int>::pointer *v52; // rdi
  std::vector<double> *v53; // rdi
  double *v54; // rax
  struct _Unwind_Exception *v55; // rbx
  std::_Vector_base<long unsigned int>::pointer v56; // rdi
  double *v57; // rdi
  double *v58; // r13
  std::_Vector_base<double>::pointer *v59; // rax
  std::_Vector_base<double>::pointer *v60; // rdi
  std::vector<float> *v61; // rdi
  float *v62; // rax
  struct _Unwind_Exception *v63; // rbx
  std::_Vector_base<double>::pointer v64; // rdi
  float *v65; // rdi
  float *v66; // r13
  std::_Vector_base<float>::pointer *v67; // rax
  std::_Vector_base<float>::pointer *v68; // rdi
  struct _Unwind_Exception *v69; // rbx
  std::_Vector_base<float>::pointer v70; // rdi
  std::string::pointer v71; // rdi
  void *v72; // rdi
  std::string *__prioritya; // [rsp+8h] [rbp-3F0h]
  std::allocator<char> v74; // [rsp+13h] [rbp-3E5h] BYREF
  std::allocator<char> v75; // [rsp+14h] [rbp-3E4h] BYREF
  std::allocator<char> v76; // [rsp+15h] [rbp-3E3h] BYREF
  std::allocator<char> v77; // [rsp+16h] [rbp-3E2h] BYREF
  std::allocator<char> v78; // [rsp+17h] [rbp-3E1h] BYREF
  std::allocator<char> v79; // [rsp+18h] [rbp-3E0h] BYREF
  std::allocator<char> v80; // [rsp+19h] [rbp-3DFh] BYREF
  std::allocator<char> v81; // [rsp+1Ah] [rbp-3DEh] BYREF
  std::allocator<char> v82; // [rsp+1Bh] [rbp-3DDh] BYREF
  std::allocator<char> v83; // [rsp+1Ch] [rbp-3DCh] BYREF
  std::allocator<char> v84; // [rsp+1Dh] [rbp-3DBh] BYREF
  std::allocator<char> v85; // [rsp+1Eh] [rbp-3DAh] BYREF
  std::allocator<char> __a; // [rsp+1Fh] [rbp-3D9h] BYREF
  int v87[4]; // [rsp+20h] [rbp-3D8h] BYREF
  int src; // [rsp+30h] [rbp-3C8h] BYREF
  int v89; // [rsp+34h] [rbp-3C4h]
  int v90; // [rsp+38h] [rbp-3C0h]
  int v91; // [rsp+3Ch] [rbp-3BCh]
  int v92; // [rsp+40h] [rbp-3B8h]
  _BYTE v93[12]; // [rsp+44h] [rbp-3B4h] BYREF
  __int64 v94[4]; // [rsp+50h] [rbp-3A8h] BYREF
  __int64 v95; // [rsp+70h] [rbp-388h] BYREF
  __int64 v96; // [rsp+78h] [rbp-380h]
  __int64 v97; // [rsp+80h] [rbp-378h]
  __int64 v98; // [rsp+88h] [rbp-370h]
  __int64 v99; // [rsp+90h] [rbp-368h]
  __int64 v100; // [rsp+98h] [rbp-360h] BYREF
  std::string v101; // [rsp+A0h] [rbp-358h] BYREF
  std::string v102; // [rsp+C0h] [rbp-338h] BYREF
  std::string v103; // [rsp+E0h] [rbp-318h] BYREF
  std::string v104; // [rsp+100h] [rbp-2F8h] BYREF
  std::string v105; // [rsp+120h] [rbp-2D8h] BYREF
  std::string v106; // [rsp+140h] [rbp-2B8h] BYREF
  std::string v107; // [rsp+160h] [rbp-298h] BYREF
  std::string v108; // [rsp+180h] [rbp-278h] BYREF
  std::string v109; // [rsp+1A0h] [rbp-258h] BYREF
  std::string v110; // [rsp+1C0h] [rbp-238h] BYREF
  std::string v111; // [rsp+1E0h] [rbp-218h] BYREF
  std::string v112; // [rsp+200h] [rbp-1F8h] BYREF
  std::string v113; // [rsp+220h] [rbp-1D8h] BYREF
  std::string v114; // [rsp+240h] [rbp-1B8h] BYREF
  std::string v115; // [rsp+260h] [rbp-198h] BYREF
  std::string v116; // [rsp+280h] [rbp-178h] BYREF
  std::string v117; // [rsp+2A0h] [rbp-158h] BYREF
  std::string v118; // [rsp+2C0h] [rbp-138h] BYREF
  std::string v119; // [rsp+2E0h] [rbp-118h] BYREF
  std::string v120; // [rsp+300h] [rbp-F8h] BYREF
  std::string v121; // [rsp+320h] [rbp-D8h] BYREF
  std::string v122; // [rsp+340h] [rbp-B8h] BYREF
  std::string v123; // [rsp+360h] [rbp-98h] BYREF
  char v124[120]; // [rsp+380h] [rbp-78h] BYREF

  LODWORD(__prioritya) = __priority;
  v2 = (unsigned __int64)v124;
  if ( _asan_option_detect_stack_use_after_return )
  {
    v5 = __asan_stack_malloc_0(64LL);
    if ( v5 )
      v2 = v5;
  }
  v3 = (int *)(v2 + 64);
  *(_QWORD *)v2 = 1102416563LL;
  *(_QWORD *)(v2 + 8) = "1 32 8 4 __an";
  *(_QWORD *)(v2 + 16) = __static_initialization_and_destruction_0;
  v4 = v2 >> 3;
  *(_DWORD *)(v4 + 2147450880) = -235802127;
  *(_DWORD *)(v4 + 2147450884) = -202116352;
  if ( __initialize_p != 1 )
    goto LABEL_3;
  __asan_before_dynamic_init("src/proto_utils.cpp");
  if ( __priority != 0xFFFF )
    goto LABEL_8;
  std::ios_base::Init::Init(&std::__ioinit);
  __cxa_atexit((void (__fastcall *)(void *))&std::ios_base::Init::~Init, &std::__ioinit, &_dso_handle);
  std::string::basic_string<std::allocator<char>>(
    (std::string *const)&ProtoConst::cmd_id_config[abi:cxx11],
    "proto.CmdIdConfig",
    &__a);
  __cxa_atexit(
    (void (__fastcall *)(void *))&std::string::~string,
    (void *)&ProtoConst::cmd_id_config[abi:cxx11],
    &_dso_handle);
  p_a = &ProtoConst::retcode[abi:cxx11];
  std::string::basic_string<std::allocator<char>>(
    (std::string *const)&ProtoConst::retcode[abi:cxx11],
    "proto.Retcode",
    &__a);
  v7 = (std::set<unsigned int> *)&ProtoConst::retcode[abi:cxx11];
  __cxa_atexit(
    (void (__fastcall *)(void *))&std::string::~string,
    (void *)&ProtoConst::retcode[abi:cxx11],
    &_dso_handle);
  p_M_parent = &ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header;
  v9 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header >> 3)
                + 0x7FFF8000);
  if ( v9 && v9 <= 3 )
  {
    __asan_report_store4(p_M_parent, &ProtoConst::retcode[abi:cxx11]);
    goto LABEL_77;
  }
  ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent >> 3)
                + 0x7FFF8000) )
  {
LABEL_77:
    __asan_report_store8(p_M_parent, &ProtoConst::retcode[abi:cxx11]);
    goto LABEL_78;
  }
  ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_left >> 3)
                + 0x7FFF8000) )
  {
LABEL_78:
    __asan_report_store8(p_M_parent, &ProtoConst::retcode[abi:cxx11]);
    goto LABEL_79;
  }
  ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_left = &ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_right >> 3)
                + 0x7FFF8000) )
  {
LABEL_79:
    __asan_report_store8(p_M_parent, &ProtoConst::retcode[abi:cxx11]);
    goto LABEL_80;
  }
  ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_right = &ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_node_count >> 3)
                + 0x7FFF8000) )
  {
LABEL_80:
    __asan_report_store8(p_M_parent, &ProtoConst::retcode[abi:cxx11]);
LABEL_81:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_82;
  }
  v7 = (std::set<unsigned int> *)&ProtoUtils::cmd_to_name_map_[abi:cxx11];
  ProtoUtils::cmd_to_name_map_[abi:cxx11]._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::map<unsigned int,std::string>::~map,
    &ProtoUtils::cmd_to_name_map_[abi:cxx11],
    &_dso_handle);
  p_M_parent = &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header;
  v10 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header >> 3)
                 + 0x7FFF8000);
  if ( v10 && v10 <= 3 )
    goto LABEL_81;
  ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent >> 3)
                + 0x7FFF8000) )
  {
LABEL_82:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_83;
  }
  ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_left >> 3)
                + 0x7FFF8000) )
  {
LABEL_83:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_84;
  }
  ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_left = &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_right >> 3)
                + 0x7FFF8000) )
  {
LABEL_84:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_85;
  }
  ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header._M_right = &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_node_count >> 3)
                + 0x7FFF8000) )
  {
LABEL_85:
    __asan_report_store8(p_M_parent, v7);
LABEL_86:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_87;
  }
  v7 = (std::set<unsigned int> *)&ProtoUtils::name_to_cmd_map_[abi:cxx11];
  ProtoUtils::name_to_cmd_map_[abi:cxx11]._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::map<std::string,unsigned int>::~map,
    &ProtoUtils::name_to_cmd_map_[abi:cxx11],
    &_dso_handle);
  p_M_parent = &ProtoUtils::cmd_to_channel_map_._M_t._M_impl.std::_Rb_tree_header;
  v11 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_channel_map_._M_t._M_impl.std::_Rb_tree_header >> 3)
                 + 0x7FFF8000);
  if ( v11 && v11 <= 3 )
    goto LABEL_86;
  ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_parent >> 3) + 0x7FFF8000) )
  {
LABEL_87:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_88;
  }
  ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_left >> 3) + 0x7FFF8000) )
  {
LABEL_88:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_89;
  }
  ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_left = &ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_right >> 3) + 0x7FFF8000) )
  {
LABEL_89:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_90;
  }
  ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header._M_right = &ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_node_count >> 3) + 0x7FFF8000) )
  {
LABEL_90:
    __asan_report_store8(p_M_parent, v7);
LABEL_91:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_92;
  }
  v7 = (std::set<unsigned int> *)&ProtoUtils::cmd_to_channel_map_;
  ProtoUtils::cmd_to_channel_map_._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::map<unsigned int,unsigned int>::~map,
    &ProtoUtils::cmd_to_channel_map_,
    &_dso_handle);
  p_M_parent = &ProtoUtils::cmd_to_desc_map_._M_t._M_impl.std::_Rb_tree_header;
  v12 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_desc_map_._M_t._M_impl.std::_Rb_tree_header >> 3) + 0x7FFF8000);
  if ( v12 && v12 <= 3 )
    goto LABEL_91;
  ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_parent >> 3) + 0x7FFF8000) )
  {
LABEL_92:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_93;
  }
  ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_left >> 3) + 0x7FFF8000) )
  {
LABEL_93:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_94;
  }
  ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_left = &ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_right >> 3) + 0x7FFF8000) )
  {
LABEL_94:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_95;
  }
  ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header._M_right = &ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_node_count >> 3) + 0x7FFF8000) )
  {
LABEL_95:
    __asan_report_store8(p_M_parent, v7);
LABEL_96:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_97;
  }
  v7 = (std::set<unsigned int> *)&ProtoUtils::cmd_to_desc_map_;
  ProtoUtils::cmd_to_desc_map_._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::map<unsigned int,google::protobuf::Descriptor const*>::~map,
    &ProtoUtils::cmd_to_desc_map_,
    &_dso_handle);
  p_M_parent = &ProtoUtils::cmd_to_type_map_._M_t._M_impl.std::_Rb_tree_header;
  v13 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_type_map_._M_t._M_impl.std::_Rb_tree_header >> 3) + 0x7FFF8000);
  if ( v13 && v13 <= 3 )
    goto LABEL_96;
  ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_parent >> 3) + 0x7FFF8000) )
  {
LABEL_97:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_98;
  }
  ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_left >> 3) + 0x7FFF8000) )
  {
LABEL_98:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_99;
  }
  ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_left = &ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_right >> 3) + 0x7FFF8000) )
  {
LABEL_99:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_100;
  }
  ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header._M_right = &ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_node_count >> 3) + 0x7FFF8000) )
  {
LABEL_100:
    __asan_report_store8(p_M_parent, v7);
LABEL_101:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_102;
  }
  v7 = (std::set<unsigned int> *)&ProtoUtils::cmd_to_type_map_;
  ProtoUtils::cmd_to_type_map_._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::map<unsigned int,ProtoCmdType>::~map,
    &ProtoUtils::cmd_to_type_map_,
    &_dso_handle);
  p_M_parent = &ProtoUtils::allow_client_cmd_set_._M_t._M_impl.std::_Rb_tree_header;
  v14 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::allow_client_cmd_set_._M_t._M_impl.std::_Rb_tree_header >> 3)
                 + 0x7FFF8000);
  if ( v14 && v14 <= 3 )
    goto LABEL_101;
  ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_parent >> 3)
                + 0x7FFF8000) )
  {
LABEL_102:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_103;
  }
  ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_left >> 3) + 0x7FFF8000) )
  {
LABEL_103:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_104;
  }
  ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_left = &ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_right >> 3)
                + 0x7FFF8000) )
  {
LABEL_104:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_105;
  }
  ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header._M_right = &ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_node_count >> 3) + 0x7FFF8000) )
  {
LABEL_105:
    __asan_report_store8(p_M_parent, v7);
LABEL_106:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_107;
  }
  v7 = &ProtoUtils::allow_client_cmd_set_;
  ProtoUtils::allow_client_cmd_set_._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::set<unsigned int>::~set,
    &ProtoUtils::allow_client_cmd_set_,
    &_dso_handle);
  p_M_parent = &ProtoUtils::reliable_cmd_set_._M_t._M_impl.std::_Rb_tree_header;
  v15 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::reliable_cmd_set_._M_t._M_impl.std::_Rb_tree_header >> 3) + 0x7FFF8000);
  if ( v15 && v15 <= 3 )
    goto LABEL_106;
  ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_parent >> 3) + 0x7FFF8000) )
  {
LABEL_107:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_108;
  }
  ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_left >> 3) + 0x7FFF8000) )
  {
LABEL_108:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_109;
  }
  ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_left = &ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_right >> 3) + 0x7FFF8000) )
  {
LABEL_109:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_110;
  }
  ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header._M_right = &ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_node_count >> 3) + 0x7FFF8000) )
  {
LABEL_110:
    __asan_report_store8(p_M_parent, v7);
LABEL_111:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_112;
  }
  v7 = &ProtoUtils::reliable_cmd_set_;
  ProtoUtils::reliable_cmd_set_._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit((void (__fastcall *)(void *))std::set<unsigned int>::~set, &ProtoUtils::reliable_cmd_set_, &_dso_handle);
  p_M_parent = &ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header;
  v16 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header >> 3)
                 + 0x7FFF8000);
  if ( v16 && v16 <= 3 )
    goto LABEL_111;
  ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent >> 3)
                + 0x7FFF8000) )
  {
LABEL_112:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_113;
  }
  ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_left >> 3)
                + 0x7FFF8000) )
  {
LABEL_113:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_114;
  }
  ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_left = &ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_right >> 3)
                + 0x7FFF8000) )
  {
LABEL_114:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_115;
  }
  ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header._M_right = &ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_node_count >> 3)
                + 0x7FFF8000) )
  {
LABEL_115:
    __asan_report_store8(p_M_parent, v7);
LABEL_116:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_117;
  }
  v7 = (std::set<unsigned int> *)&ProtoUtils::cmd_id_config_map_[abi:cxx11];
  ProtoUtils::cmd_id_config_map_[abi:cxx11]._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::map<std::string,ProtoUtils::CmdIdConfig>::~map,
    &ProtoUtils::cmd_id_config_map_[abi:cxx11],
    &_dso_handle);
  p_M_parent = &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header;
  v17 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header >> 3)
                 + 0x7FFF8000);
  if ( v17 && v17 <= 3 )
    goto LABEL_116;
  ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent >> 3)
                + 0x7FFF8000) )
  {
LABEL_117:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_118;
  }
  ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_left >> 3)
                + 0x7FFF8000) )
  {
LABEL_118:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_119;
  }
  ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_left = &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_right >> 3)
                + 0x7FFF8000) )
  {
LABEL_119:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_120;
  }
  ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header._M_right = &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_node_count >> 3)
                + 0x7FFF8000) )
  {
LABEL_120:
    __asan_report_store8(p_M_parent, v7);
LABEL_121:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_122;
  }
  v7 = (std::set<unsigned int> *)&ProtoUtils::retcode_to_name_map_[abi:cxx11];
  ProtoUtils::retcode_to_name_map_[abi:cxx11]._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::map<int,std::string>::~map,
    &ProtoUtils::retcode_to_name_map_[abi:cxx11],
    &_dso_handle);
  p_M_parent = &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header;
  v18 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header >> 3)
                 + 0x7FFF8000);
  if ( v18 && v18 <= 3 )
    goto LABEL_121;
  ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent >> 3)
                + 0x7FFF8000) )
  {
LABEL_122:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_123;
  }
  ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_left >> 3)
                + 0x7FFF8000) )
  {
LABEL_123:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_124;
  }
  ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_left = &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_right >> 3)
                + 0x7FFF8000) )
  {
LABEL_124:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_125;
  }
  ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header._M_right = &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_node_count >> 3)
                + 0x7FFF8000) )
  {
LABEL_125:
    __asan_report_store8(p_M_parent, v7);
LABEL_126:
    __asan_report_store4(p_M_parent, v7);
    goto LABEL_127;
  }
  ProtoUtils::retcode_to_value_map_[abi:cxx11]._M_t._M_impl._M_node_count = 0LL;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::map<std::string,int>::~map,
    &ProtoUtils::retcode_to_value_map_[abi:cxx11],
    &_dso_handle);
  p_a = (const std::string *)&__a;
  std::string::basic_string<std::allocator<char>>(&ProtoUtils::default_cmd_name_[abi:cxx11], "unknow", &__a);
  __cxa_atexit(
    (void (__fastcall *)(void *))&std::string::~string,
    &ProtoUtils::default_cmd_name_[abi:cxx11],
    &_dso_handle);
  std::string::basic_string<std::allocator<char>>(&ProtoUtils::default_retcode_name_[abi:cxx11], "unknow", &__a);
  __cxa_atexit(
    (void (__fastcall *)(void *))&std::string::~string,
    &ProtoUtils::default_retcode_name_[abi:cxx11],
    &_dso_handle);
  __prioritya = &v101;
  std::string::basic_string<std::allocator<char>>(&v101, "GetPlayerTokenReq", &v76);
  std::string::basic_string<std::allocator<char>>(&v102, "PlayerLoginReq", &v77);
  std::string::basic_string<std::allocator<char>>(&v103, "PlayerLogoutReq", &v78);
  std::string::basic_string<std::allocator<char>>(&v104, "JoinPlayerSceneReq", &v79);
  std::string::basic_string<std::allocator<char>>(&v105, "BackMyWorldReq", &v80);
  std::string::basic_string<std::allocator<char>>(&v106, "PlayerForceExitReq", &v81);
  std::string::basic_string<std::allocator<char>>(&v107, "EnterSceneReadyReq", &v82);
  std::string::basic_string<std::allocator<char>>(&v108, "SceneInitFinishReq", &v83);
  std::string::basic_string<std::allocator<char>>(&v109, "EnterSceneDoneReq", &v84);
  std::string::basic_string<std::allocator<char>>(&v110, "PostEnterSceneReq", &v85);
  v7 = (std::set<unsigned int> *)"GmTalkReq";
  std::string::basic_string<std::allocator<char>>(&v111, "GmTalkReq", &__a);
  p_M_parent = &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header;
  v19 = *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header >> 3)
                 + 0x7FFF8000);
  if ( v19 && v19 <= 3 )
    goto LABEL_126;
  ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_color = _S_red;
  p_M_parent = &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_parent;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_parent >> 3)
                + 0x7FFF8000) )
  {
LABEL_127:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_128;
  }
  ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_parent = 0LL;
  p_M_parent = &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_left;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_left >> 3)
                + 0x7FFF8000) )
  {
LABEL_128:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_129;
  }
  ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_left = &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_right;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_right >> 3)
                + 0x7FFF8000) )
  {
LABEL_129:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_130;
  }
  ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header._M_right = &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_header;
  p_M_parent = &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_node_count;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_node_count >> 3)
                + 0x7FFF8000) )
  {
LABEL_130:
    __asan_report_store8(p_M_parent, v7);
    goto LABEL_131;
  }
  ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl._M_node_count = 0LL;
  p_a = &v101;
  __prioritya = &v112;
  *(_QWORD *)(v2 + 32) = &ProtoUtils::TamperUtils::black_list[abi:cxx11];
  while ( __prioritya != p_a )
  {
    std::_Rb_tree<std::string,std::string,std::_Identity<std::string>,std::less<std::string>,std::allocator<std::string>>::_M_insert_unique_<std::string const&,std::_Rb_tree<std::string,std::string,std::_Identity<std::string>,std::less<std::string>,std::allocator<std::string>>::_Alloc_node>(
      &ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t,
      (std::_Rb_tree<std::string,std::string,std::_Identity<std::string >,std::less<std::string >,std::allocator<std::string > >::const_iterator)&ProtoUtils::TamperUtils::black_list[abi:cxx11]._M_t._M_impl.std::_Rb_tree_header,
      p_a,
      (std::_Rb_tree<std::string,std::string,std::_Identity<std::string >,std::less<std::string >,std::allocator<std::string > >::_Alloc_node *)(v2 + 32));
LABEL_131:
    ++p_a;
  }
  v20 = &v112;
  while ( v20 != &v101 )
  {
    M_p = (std::string::pointer)--v20;
    if ( *(_BYTE *)(((unsigned __int64)v20 >> 3) + 0x7FFF8000) )
    {
LABEL_138:
      __asan_report_load8(M_p);
      goto LABEL_139;
    }
    M_p = v20->_M_dataplus._M_p;
    if ( &v20->_anon_0 != (std::string::$CFBEC286C7F52157F7E59FC354047095 *)v20->_M_dataplus._M_p )
LABEL_139:
      operator delete(M_p);
  }
  p_src = (__int64 *)&ProtoUtils::TamperUtils::black_list[abi:cxx11];
  __cxa_atexit(
    (void (__fastcall *)(void *))std::set<std::string>::~set,
    &ProtoUtils::TamperUtils::black_list[abi:cxx11],
    &_dso_handle);
  src = 0;
  v89 = 1;
  v90 = 10;
  v91 = 0x80000000;
  v92 = 0x7FFFFFFF;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector >> 3) + 0x7FFF8000) )
  {
    p_M_finish = &ProtoUtils::TamperUtils::int32Vector;
    __asan_report_store8(&ProtoUtils::TamperUtils::int32Vector, &ProtoUtils::TamperUtils::black_list[abi:cxx11]);
    goto LABEL_149;
  }
  ProtoUtils::TamperUtils::int32Vector._M_impl._M_start = 0LL;
  p_M_finish = (std::vector<int> *)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
  {
LABEL_149:
    __asan_report_store8(p_M_finish, &ProtoUtils::TamperUtils::black_list[abi:cxx11]);
    goto LABEL_150;
  }
  ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish = 0LL;
  p_M_finish = (std::vector<int> *)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_end_of_storage;
  if ( !*(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
  {
    ProtoUtils::TamperUtils::int32Vector._M_impl._M_end_of_storage = 0LL;
    v3 = (int *)v93;
    v24 = (int *)operator new(0x14uLL);
    goto LABEL_151;
  }
LABEL_150:
  v24 = (int *)__asan_report_store8(p_M_finish, &ProtoUtils::TamperUtils::black_list[abi:cxx11]);
LABEL_151:
  v25 = v24;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector >> 3) + 0x7FFF8000) )
  {
    p_M_end_of_storage = (std::_Vector_base<int>::pointer *)__asan_report_store8(
                                                              &ProtoUtils::TamperUtils::int32Vector,
                                                              &ProtoUtils::TamperUtils::black_list[abi:cxx11]);
LABEL_161:
    v28 = p_M_end_of_storage;
    __asan_report_store8(p_M_end_of_storage, &ProtoUtils::TamperUtils::black_list[abi:cxx11]);
LABEL_162:
    __asan_report_store8(v28, p_src);
LABEL_163:
    v29 = &ProtoUtils::TamperUtils::int64Vector;
    __asan_report_store8(&ProtoUtils::TamperUtils::int64Vector, p_src);
LABEL_164:
    __asan_report_store8(v29, p_src);
LABEL_165:
    v31 = (struct _Unwind_Exception *)__asan_report_store8(v29, p_src);
    if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector >> 3) + 0x7FFF8000) )
      __asan_report_load8(&ProtoUtils::TamperUtils::int32Vector);
    M_start = ProtoUtils::TamperUtils::int32Vector._M_impl._M_start;
    if ( ProtoUtils::TamperUtils::int32Vector._M_impl._M_start )
      operator delete(ProtoUtils::TamperUtils::int32Vector._M_impl._M_start);
    __asan_handle_no_return(M_start);
    _Unwind_Resume(v31);
  }
  ProtoUtils::TamperUtils::int32Vector._M_impl._M_start = v24;
  v26 = v24 + 5;
  p_M_end_of_storage = &ProtoUtils::TamperUtils::int32Vector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_161;
  ProtoUtils::TamperUtils::int32Vector._M_impl._M_end_of_storage = v26;
  if ( &src != v3 )
  {
    p_src = (__int64 *)&src;
    memmove(v25, &src, 0x14uLL);
  }
  v28 = &ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_162;
  p_src = (__int64 *)&ProtoUtils::TamperUtils::int32Vector;
  ProtoUtils::TamperUtils::int32Vector._M_impl._M_finish = v26;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::vector<int>::~vector,
    &ProtoUtils::TamperUtils::int32Vector,
    &_dso_handle);
  v95 = 0LL;
  v96 = 1LL;
  v97 = 10LL;
  v98 = 0x8000000000000000LL;
  v99 = 0x7FFFFFFFFFFFFFFFLL;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector >> 3) + 0x7FFF8000) )
    goto LABEL_163;
  ProtoUtils::TamperUtils::int64Vector._M_impl._M_start = 0LL;
  v29 = (std::vector<long int> *)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_164;
  ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish = 0LL;
  v29 = (std::vector<long int> *)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_165;
  ProtoUtils::TamperUtils::int64Vector._M_impl._M_end_of_storage = 0LL;
  v30 = (__int64 *)operator new(0x28uLL);
  v33 = v30;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector >> 3) + 0x7FFF8000) )
  {
    v35 = (std::_Vector_base<long int>::pointer *)__asan_report_store8(
                                                    &ProtoUtils::TamperUtils::int64Vector,
                                                    &ProtoUtils::TamperUtils::int32Vector);
LABEL_180:
    v36 = v35;
    __asan_report_store8(v35, &ProtoUtils::TamperUtils::int32Vector);
LABEL_181:
    __asan_report_store8(v36, p_src);
LABEL_182:
    v37 = &ProtoUtils::TamperUtils::uInt32Vector;
    __asan_report_store8(&ProtoUtils::TamperUtils::uInt32Vector, p_src);
LABEL_183:
    __asan_report_store8(v37, p_src);
LABEL_184:
    v39 = (struct _Unwind_Exception *)__asan_report_store8(v37, p_src);
    if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector >> 3) + 0x7FFF8000) )
      __asan_report_load8(&ProtoUtils::TamperUtils::int64Vector);
    v40 = ProtoUtils::TamperUtils::int64Vector._M_impl._M_start;
    if ( ProtoUtils::TamperUtils::int64Vector._M_impl._M_start )
      operator delete(ProtoUtils::TamperUtils::int64Vector._M_impl._M_start);
    __asan_handle_no_return(v40);
    _Unwind_Resume(v39);
  }
  ProtoUtils::TamperUtils::int64Vector._M_impl._M_start = v30;
  v34 = v30 + 5;
  v35 = &ProtoUtils::TamperUtils::int64Vector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_180;
  ProtoUtils::TamperUtils::int64Vector._M_impl._M_end_of_storage = v34;
  if ( &v95 != &v100 )
  {
    p_src = &v95;
    memmove(v33, &v95, 0x28uLL);
  }
  v36 = &ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_181;
  p_src = (__int64 *)&ProtoUtils::TamperUtils::int64Vector;
  ProtoUtils::TamperUtils::int64Vector._M_impl._M_finish = v34;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::vector<long>::~vector,
    &ProtoUtils::TamperUtils::int64Vector,
    &_dso_handle);
  v87[0] = 0;
  v87[1] = 1;
  v87[2] = 10;
  v87[3] = -1;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector >> 3) + 0x7FFF8000) )
    goto LABEL_182;
  ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start = 0LL;
  v37 = (std::vector<unsigned int> *)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_183;
  ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish = 0LL;
  v37 = (std::vector<unsigned int> *)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_184;
  ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_end_of_storage = 0LL;
  v38 = (unsigned int *)operator new(0x10uLL);
  v41 = v38;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector >> 3) + 0x7FFF8000) )
  {
    v43 = (std::_Vector_base<unsigned int>::pointer *)__asan_report_store8(
                                                        &ProtoUtils::TamperUtils::uInt32Vector,
                                                        &ProtoUtils::TamperUtils::int64Vector);
LABEL_199:
    v44 = v43;
    __asan_report_store8(v43, &ProtoUtils::TamperUtils::int64Vector);
LABEL_200:
    __asan_report_store8(v44, p_src);
LABEL_201:
    v45 = &ProtoUtils::TamperUtils::uInt64Vector;
    __asan_report_store8(&ProtoUtils::TamperUtils::uInt64Vector, p_src);
LABEL_202:
    __asan_report_store8(v45, p_src);
LABEL_203:
    v47 = (struct _Unwind_Exception *)__asan_report_store8(v45, p_src);
    if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector >> 3) + 0x7FFF8000) )
      __asan_report_load8(&ProtoUtils::TamperUtils::uInt32Vector);
    v48 = ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start;
    if ( ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start )
      operator delete(ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start);
    __asan_handle_no_return(v48);
    _Unwind_Resume(v47);
  }
  ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_start = v38;
  v42 = v38 + 4;
  v43 = &ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_199;
  ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_end_of_storage = v42;
  if ( v87 != &src )
  {
    p_src = (__int64 *)v87;
    memmove(v41, v87, 0x10uLL);
  }
  v44 = &ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_200;
  p_src = (__int64 *)&ProtoUtils::TamperUtils::uInt32Vector;
  ProtoUtils::TamperUtils::uInt32Vector._M_impl._M_finish = v42;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::vector<unsigned int>::~vector,
    &ProtoUtils::TamperUtils::uInt32Vector,
    &_dso_handle);
  v94[0] = 0LL;
  v94[1] = 1LL;
  v94[2] = 10LL;
  v94[3] = -1LL;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector >> 3) + 0x7FFF8000) )
    goto LABEL_201;
  ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start = 0LL;
  v45 = (std::vector<long unsigned int> *)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_202;
  ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish = 0LL;
  v45 = (std::vector<long unsigned int> *)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_203;
  ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_end_of_storage = 0LL;
  v46 = (unsigned __int64 *)operator new(0x20uLL);
  v49 = v46;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector >> 3) + 0x7FFF8000) )
  {
    v51 = (std::_Vector_base<long unsigned int>::pointer *)__asan_report_store8(
                                                             &ProtoUtils::TamperUtils::uInt64Vector,
                                                             &ProtoUtils::TamperUtils::uInt32Vector);
LABEL_218:
    v52 = v51;
    __asan_report_store8(v51, &ProtoUtils::TamperUtils::uInt32Vector);
LABEL_219:
    __asan_report_store8(v52, p_src);
LABEL_220:
    v53 = &ProtoUtils::TamperUtils::doubleVector;
    __asan_report_store8(&ProtoUtils::TamperUtils::doubleVector, p_src);
LABEL_221:
    __asan_report_store8(v53, p_src);
LABEL_222:
    v55 = (struct _Unwind_Exception *)__asan_report_store8(v53, p_src);
    if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector >> 3) + 0x7FFF8000) )
      __asan_report_load8(&ProtoUtils::TamperUtils::uInt64Vector);
    v56 = ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start;
    if ( ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start )
      operator delete(ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start);
    __asan_handle_no_return(v56);
    _Unwind_Resume(v55);
  }
  ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_start = v46;
  v50 = v46 + 4;
  v51 = &ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_218;
  ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_end_of_storage = v50;
  if ( v94 != &v95 )
  {
    p_src = v94;
    memmove(v49, v94, 0x20uLL);
  }
  v52 = &ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_219;
  p_src = (__int64 *)&ProtoUtils::TamperUtils::uInt64Vector;
  ProtoUtils::TamperUtils::uInt64Vector._M_impl._M_finish = v50;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::vector<unsigned long>::~vector,
    &ProtoUtils::TamperUtils::uInt64Vector,
    &_dso_handle);
  v95 = 0LL;
  v96 = 0xC5CD14A0219A79A5LL;
  v97 = 0x4458650127CC3DC8LL;
  v98 = 0xBFBC71C71C71C71CLL;
  v99 = 0x3FF5555555555555LL;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector >> 3) + 0x7FFF8000) )
    goto LABEL_220;
  ProtoUtils::TamperUtils::doubleVector._M_impl._M_start = 0LL;
  v53 = (std::vector<double> *)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_221;
  ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish = 0LL;
  v53 = (std::vector<double> *)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_222;
  ProtoUtils::TamperUtils::doubleVector._M_impl._M_end_of_storage = 0LL;
  v54 = (double *)operator new(0x28uLL);
  v57 = v54;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector >> 3) + 0x7FFF8000) )
  {
    v59 = (std::_Vector_base<double>::pointer *)__asan_report_store8(
                                                  &ProtoUtils::TamperUtils::doubleVector,
                                                  &ProtoUtils::TamperUtils::uInt64Vector);
LABEL_237:
    v60 = v59;
    __asan_report_store8(v59, &ProtoUtils::TamperUtils::uInt64Vector);
LABEL_238:
    __asan_report_store8(v60, p_src);
LABEL_239:
    v61 = &ProtoUtils::TamperUtils::floatVector;
    __asan_report_store8(&ProtoUtils::TamperUtils::floatVector, p_src);
LABEL_240:
    __asan_report_store8(v61, p_src);
LABEL_241:
    v63 = (struct _Unwind_Exception *)__asan_report_store8(v61, p_src);
    if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector >> 3) + 0x7FFF8000) )
      __asan_report_load8(&ProtoUtils::TamperUtils::doubleVector);
    v64 = ProtoUtils::TamperUtils::doubleVector._M_impl._M_start;
    if ( ProtoUtils::TamperUtils::doubleVector._M_impl._M_start )
      operator delete(ProtoUtils::TamperUtils::doubleVector._M_impl._M_start);
    __asan_handle_no_return(v64);
    _Unwind_Resume(v63);
  }
  ProtoUtils::TamperUtils::doubleVector._M_impl._M_start = v54;
  v58 = v54 + 5;
  v59 = &ProtoUtils::TamperUtils::doubleVector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_237;
  ProtoUtils::TamperUtils::doubleVector._M_impl._M_end_of_storage = v58;
  if ( &v95 != &v100 )
  {
    p_src = &v95;
    memmove(v57, &v95, 0x28uLL);
  }
  v60 = &ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_238;
  p_src = (__int64 *)&ProtoUtils::TamperUtils::doubleVector;
  ProtoUtils::TamperUtils::doubleVector._M_impl._M_finish = v58;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::vector<double>::~vector,
    &ProtoUtils::TamperUtils::doubleVector,
    &_dso_handle);
  src = 0;
  v89 = -712837219;
  v90 = 1518324638;
  v91 = -1109160391;
  v92 = 1068149419;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector >> 3) + 0x7FFF8000) )
    goto LABEL_239;
  ProtoUtils::TamperUtils::floatVector._M_impl._M_start = 0LL;
  v61 = (std::vector<float> *)&ProtoUtils::TamperUtils::floatVector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_240;
  ProtoUtils::TamperUtils::floatVector._M_impl._M_finish = 0LL;
  v61 = (std::vector<float> *)&ProtoUtils::TamperUtils::floatVector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_241;
  ProtoUtils::TamperUtils::floatVector._M_impl._M_end_of_storage = 0LL;
  v3 = (int *)v93;
  v62 = (float *)operator new(0x14uLL);
  v65 = v62;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector >> 3) + 0x7FFF8000) )
  {
    v67 = (std::_Vector_base<float>::pointer *)__asan_report_store8(
                                                 &ProtoUtils::TamperUtils::floatVector,
                                                 &ProtoUtils::TamperUtils::doubleVector);
LABEL_253:
    v68 = v67;
    __asan_report_store8(v67, &ProtoUtils::TamperUtils::doubleVector);
LABEL_254:
    v69 = (struct _Unwind_Exception *)__asan_report_store8(v68, p_src);
    if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector >> 3) + 0x7FFF8000) )
      __asan_report_load8(&ProtoUtils::TamperUtils::floatVector);
    v70 = ProtoUtils::TamperUtils::floatVector._M_impl._M_start;
    if ( ProtoUtils::TamperUtils::floatVector._M_impl._M_start )
      operator delete(ProtoUtils::TamperUtils::floatVector._M_impl._M_start);
    __asan_handle_no_return(v70);
    _Unwind_Resume(v69);
  }
  ProtoUtils::TamperUtils::floatVector._M_impl._M_start = v62;
  v66 = v62 + 5;
  v67 = &ProtoUtils::TamperUtils::floatVector._M_impl._M_end_of_storage;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_end_of_storage >> 3) + 0x7FFF8000) )
    goto LABEL_253;
  ProtoUtils::TamperUtils::floatVector._M_impl._M_end_of_storage = v66;
  if ( &src != (int *)v93 )
  {
    p_src = (__int64 *)&src;
    memmove(v65, &src, 0x14uLL);
  }
  v68 = &ProtoUtils::TamperUtils::floatVector._M_impl._M_finish;
  if ( *(_BYTE *)(((unsigned __int64)&ProtoUtils::TamperUtils::floatVector._M_impl._M_finish >> 3) + 0x7FFF8000) )
    goto LABEL_254;
  ProtoUtils::TamperUtils::floatVector._M_impl._M_finish = v66;
  __cxa_atexit(
    (void (__fastcall *)(void *))std::vector<float>::~vector,
    &ProtoUtils::TamperUtils::floatVector,
    &_dso_handle);
  std::string::basic_string<std::allocator<char>>(&v112, byte_19E8D240, &v74);
  std::string::basic_string<std::allocator<char>>(&v113, "'", &v75);
  std::string::basic_string<std::allocator<char>>(&v114, "/////////", &v76);
  std::string::basic_string<std::allocator<char>>(&v115, ".........", &v77);
  std::string::basic_string<std::allocator<char>>(&v116, "->", &v78);
  std::string::basic_string<std::allocator<char>>(&v117, "*********", &v79);
  std::string::basic_string<std::allocator<char>>(&v118, "\n", &v80);
  std::string::basic_string<std::allocator<char>>(&v119, "hello world!", &v81);
  std::string::basic_string<std::allocator<char>>(&v120, &byte_19E8D440, &v82);
  std::string::basic_string<std::allocator<char>>(&v121, &byte_19E8D480, &v83);
  std::string::basic_string<std::allocator<char>>(&v122, &byte_19E8D4C0, &v84);
  std::string::basic_string<std::allocator<char>>(&v123, aMihoyoandroid, &v85);
  std::vector<std::string>::vector(
    &ProtoUtils::TamperUtils::stringVector[abi:cxx11],
    (std::initializer_list<std::string >)__PAIR128__(12LL, &v112),
    (const std::vector<std::string>::allocator_type *)&__a);
  v20 = (std::string *)v124;
LABEL_261:
  while ( v20 != &v112 )
  {
    v71 = (std::string::pointer)--v20;
    if ( *(_BYTE *)(((unsigned __int64)v20 >> 3) + 0x7FFF8000) )
    {
      __asan_report_load8(v20);
LABEL_260:
      operator delete(v71);
      goto LABEL_261;
    }
    v71 = v20->_M_dataplus._M_p;
    if ( (std::string::$CFBEC286C7F52157F7E59FC354047095 *)v20->_M_dataplus._M_p != &v20->_anon_0 )
      goto LABEL_260;
  }
  __cxa_atexit(
    (void (__fastcall *)(void *))std::vector<std::string>::~vector,
    &ProtoUtils::TamperUtils::stringVector[abi:cxx11],
    &_dso_handle);
  if ( `guard variable for common::tools::StringStream<common::tools::FixedBuffer<16384>>::zero )
    goto LABEL_8;
  `guard variable for common::tools::StringStream<common::tools::FixedBuffer<16384>>::zero = 1;
  if ( *(_BYTE *)(((unsigned __int64)&common::tools::StringStream<common::tools::FixedBuffer<16384>>::zero >> 3)
                + 0x7FFF8000) )
  {
    __asan_report_store8(
      &common::tools::StringStream<common::tools::FixedBuffer<16384>>::zero,
      &ProtoUtils::TamperUtils::stringVector[abi:cxx11]);
    do
    {
      v72 = *(void **)v2;
      if ( *(_QWORD *)v2 != v2 + 16 )
        operator delete(v72);
      if ( (std::string *)v2 == &v101 )
      {
        __asan_handle_no_return(v72);
        _Unwind_Resume((struct _Unwind_Exception *)v4);
      }
      v2 -= 32LL;
      M_p = (std::string::pointer)v2;
    }
    while ( !*(_BYTE *)((v2 >> 3) + 0x7FFF8000) );
    __asan_report_load8(v2);
    goto LABEL_138;
  }
  common::tools::StringStream<common::tools::FixedBuffer<16384>>::zero = common::tools::StringStream<common::tools::FixedBuffer<16384>>::digits
                                                                       + 9;
LABEL_8:
  __asan_after_dynamic_init();
LABEL_3:
  if ( v124 == (char *)v2 )
  {
    *(_QWORD *)(v4 + 2147450880) = 0LL;
  }
  else
  {
    *(_QWORD *)v2 = 1172321806LL;
    *(_QWORD *)(v4 + 2147450880) = 0xF5F5F5F5F5F5F5F5LL;
  }
};
