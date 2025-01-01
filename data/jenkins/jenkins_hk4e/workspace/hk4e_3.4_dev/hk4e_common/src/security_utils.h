// security_utils.h

#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <string>
#include <set>
#include <vector>
#include <map>
#include <unordered_map>
#include <regex>
#include <memory>

namespace common {
    namespace milog {
        class DescribalBase {
        public:
            DescribalBase() {}
            virtual ~DescribalBase() {}
        };
    }
}

class BaseAntiCheatLogConfig : public common::milog::DescribalBase {
public:
    BaseAntiCheatLogConfig();
    ~BaseAntiCheatLogConfig();

    bool is_enable;
    int log_interval;
    int log_limit;
};

BaseAntiCheatLogConfig::BaseAntiCheatLogConfig() {
    is_enable = 1;
    log_interval = 600;
    log_limit = 100;
}

BaseAntiCheatLogConfig::~BaseAntiCheatLogConfig() {}

class SecurityAntiOfflineSwitchConfig {
public:
    SecurityAntiOfflineSwitchConfig();
    SecurityAntiOfflineSwitchConfig(const SecurityAntiOfflineSwitchConfig &other);
    ~SecurityAntiOfflineSwitchConfig();

    bool is_anti_offline_open;
    uint32_t forbid_login_level;
    uint32_t max_check_level;
    std::set<unsigned int> forbid_login_result_type_set;
};

SecurityAntiOfflineSwitchConfig::SecurityAntiOfflineSwitchConfig() {
    is_anti_offline_open = 0;
    forbid_login_level = 0;
    max_check_level = 0;
}

SecurityAntiOfflineSwitchConfig::SecurityAntiOfflineSwitchConfig(const SecurityAntiOfflineSwitchConfig &other) {
    is_anti_offline_open = other.is_anti_offline_open;
    forbid_login_level = other.forbid_login_level;
    max_check_level = other.max_check_level;
    forbid_login_result_type_set = other.forbid_login_result_type_set;
}

SecurityAntiOfflineSwitchConfig::~SecurityAntiOfflineSwitchConfig() {
    forbid_login_result_type_set.clear();
}

class SegmentCrcModuleConfig {
public:
    SegmentCrcModuleConfig();
    SegmentCrcModuleConfig(const SegmentCrcModuleConfig &other);
    ~SegmentCrcModuleConfig();

    uint32_t crc_module_index;
    uint32_t crc_module_type;
    std::string crc_module_file_str;
};

SegmentCrcModuleConfig::SegmentCrcModuleConfig() {
    crc_module_index = 0;
    crc_module_type = 0;
}

SegmentCrcModuleConfig::SegmentCrcModuleConfig(const SegmentCrcModuleConfig &other) {
    crc_module_index = other.crc_module_index;
    crc_module_type = other.crc_module_type;
    crc_module_file_str = other.crc_module_file_str;
}

SegmentCrcModuleConfig::~SegmentCrcModuleConfig() {}

class SegmentCrcPlatformConfig {
public:
    SegmentCrcPlatformConfig();
    SegmentCrcPlatformConfig(const SegmentCrcPlatformConfig &other);
    ~SegmentCrcPlatformConfig();

    uint32_t platform_type;
    std::string platform_dir_str;
    std::vector<SegmentCrcModuleConfig> crc_module_config_vec;
};

SegmentCrcPlatformConfig::SegmentCrcPlatformConfig() {
    platform_type = 0;
}

SegmentCrcPlatformConfig::SegmentCrcPlatformConfig(const SegmentCrcPlatformConfig &other) {
    platform_type = other.platform_type;
    platform_dir_str = other.platform_dir_str;
    crc_module_config_vec = other.crc_module_config_vec;
}

SegmentCrcPlatformConfig::~SegmentCrcPlatformConfig() {
    crc_module_config_vec.clear();
}

class EnvironmentErrorConfig {
public:
    EnvironmentErrorConfig();
    EnvironmentErrorConfig(const EnvironmentErrorConfig &other);
    ~EnvironmentErrorConfig();

    bool is_open;
    bool is_check_black_regex;
    std::regex white_regex;
    std::regex black_regex;
};

EnvironmentErrorConfig::EnvironmentErrorConfig() {
    is_open = 0;
    is_check_black_regex = 0;
}

EnvironmentErrorConfig::EnvironmentErrorConfig(const EnvironmentErrorConfig &other) {
    is_open = other.is_open;
    white_regex = other.white_regex;
    is_check_black_regex = other.is_check_black_regex;
    black_regex = other.black_regex;
}

EnvironmentErrorConfig::~EnvironmentErrorConfig() {}

class SafeServerConfig {
public:
    SafeServerConfig();
    ~SafeServerConfig();

    struct ConnectionStatusNotifyConfig {
        ConnectionStatusNotifyConfig();
        ~ConnectionStatusNotifyConfig();

        bool is_enable;
        std::string host;
        std::string port;
        std::string login_uri;
        std::string logout_uri;
        std::string heartbeat_uri;
        bool is_ssl;
        std::string method;
        int timeout;
        int heartbeat_interval;
        std::map<std::string, std::string> head_map;
    } connection_status_notify_config;

    std::unordered_map<unsigned int, unsigned int> security_platform_map;
};

SafeServerConfig::SafeServerConfig() {
    new (&connection_status_notify_config) ConnectionStatusNotifyConfig();
}

SafeServerConfig::~SafeServerConfig() {
    connection_status_notify_config.~ConnectionStatusNotifyConfig();
}

SafeServerConfig::ConnectionStatusNotifyConfig::ConnectionStatusNotifyConfig() {
    is_enable = 0;
    timeout = 0;
    heartbeat_interval = 0;
}

SafeServerConfig::ConnectionStatusNotifyConfig::~ConnectionStatusNotifyConfig() {
    head_map.clear();
}

class CheckQiandaoguaConfig {
public:
    CheckQiandaoguaConfig();

    bool is_enable;
    int attack_count_limit;
    int record_entry_limit;
    int anticheat_log_limit;
};

CheckQiandaoguaConfig::CheckQiandaoguaConfig() {
    is_enable = 1;
    attack_count_limit = 1;
    record_entry_limit = 100;
    anticheat_log_limit = 100;
}

class ClientTotalTickTimeConfig {
public:
    ClientTotalTickTimeConfig();

    double max_delay_time;
    int anticheat_log_limit;
};

ClientTotalTickTimeConfig::ClientTotalTickTimeConfig() {
    max_delay_time = 30.0;
    anticheat_log_limit = 100;
}

class ClientServerGlobalValueConfig {
public:
    ClientServerGlobalValueConfig();
    ~ClientServerGlobalValueConfig();

    bool is_open;
    std::string sgv_name;
    int timeout_seconds;
    int anticheat_log_limit;
};

ClientServerGlobalValueConfig::ClientServerGlobalValueConfig() {
    is_open = 0;
    timeout_seconds = 10;
    anticheat_log_limit = 100;
}

ClientServerGlobalValueConfig::~ClientServerGlobalValueConfig() {
    sgv_name.clear();
}

class SecurityAntiOfflineLevelConfig {
public:
    SecurityAntiOfflineLevelConfig();

    int down_grade_num;
    int up_grade_num;
};

SecurityAntiOfflineLevelConfig::SecurityAntiOfflineLevelConfig() {
    down_grade_num = 0;
    up_grade_num = 0;
}

class StaminaCheckConfig {
public:
    StaminaCheckConfig();

    bool is_enable;
    double record_limit;
    double low_limit;
    int anticheat_log_limit;
};

StaminaCheckConfig::StaminaCheckConfig() {
    is_enable = 1;
    record_limit = -10.0;
    low_limit = -500.0;
    anticheat_log_limit = 100;
}

class PacketCostTimeExceedLimitConfig : public BaseAntiCheatLogConfig {
public:
    PacketCostTimeExceedLimitConfig();
    ~PacketCostTimeExceedLimitConfig();

    long long check_interval_ms;
    long long cost_time_percent;
    bool is_enable_kick;
    long long kick_time_percent;
    int check_kick_interval;
    int trigger_kick_count;
    int thread_kick_interval;
};

PacketCostTimeExceedLimitConfig::PacketCostTimeExceedLimitConfig() {
    check_interval_ms = 5000LL;
    cost_time_percent = 50LL;
    is_enable_kick = 0;
    kick_time_percent = 80LL;
    check_kick_interval = 60;
    trigger_kick_count = 2;
    thread_kick_interval = 60;
}

PacketCostTimeExceedLimitConfig::~PacketCostTimeExceedLimitConfig() {}

class RecvPacketFreqExceedLimitConfig : public BaseAntiCheatLogConfig {
public:
    RecvPacketFreqExceedLimitConfig();
    ~RecvPacketFreqExceedLimitConfig();
};

RecvPacketFreqExceedLimitConfig::RecvPacketFreqExceedLimitConfig() {}

RecvPacketFreqExceedLimitConfig::~RecvPacketFreqExceedLimitConfig() {}

class SinglePacketFreqExceedLimitConfig : public BaseAntiCheatLogConfig {
public:
    SinglePacketFreqExceedLimitConfig();
    ~SinglePacketFreqExceedLimitConfig();
};

SinglePacketFreqExceedLimitConfig::SinglePacketFreqExceedLimitConfig() {}

SinglePacketFreqExceedLimitConfig::~SinglePacketFreqExceedLimitConfig() {}

class GadgetInteractBeyondCheckDistanceConfig : public BaseAntiCheatLogConfig {
public:
    GadgetInteractBeyondCheckDistanceConfig();
    ~GadgetInteractBeyondCheckDistanceConfig();

    int min_record_count;
};

GadgetInteractBeyondCheckDistanceConfig::GadgetInteractBeyondCheckDistanceConfig() {
    min_record_count = 5;
}

GadgetInteractBeyondCheckDistanceConfig::~GadgetInteractBeyondCheckDistanceConfig() {}

class LuaShellSecurityConfig {
public:
    LuaShellSecurityConfig();

    bool is_check_timeout_open;
    int lua_shell_timeout_seconds;
};

LuaShellSecurityConfig::LuaShellSecurityConfig() {
    is_check_timeout_open = 1;
    lua_shell_timeout_seconds = 60;
}

class AttackDamageReportConfig : public BaseAntiCheatLogConfig {
public:
    AttackDamageReportConfig();
    ~AttackDamageReportConfig();

    double min_report_damage;
};

AttackDamageReportConfig::AttackDamageReportConfig() {
    min_report_damage = 0.0;
}

AttackDamageReportConfig::~AttackDamageReportConfig() {}

class SecurityConfig {
public:
    SecurityConfig();
    ~SecurityConfig();

    std::map<unsigned int, SecurityAntiOfflineSwitchConfig> platform_switch_map;
    std::map<unsigned int, SecurityAntiOfflineLevelConfig> level_config_map;
    bool is_other_platform_need_check_anti_offline;
    bool is_sec_channel_open;
    bool is_checksum_version_not_found_forbid_login;
    bool is_check_client_verion_hash_fail_forbid_login;
    bool is_segment_crc_open;
    bool is_checksum_version_not_found_segment_crc_default_open;
    int segment_crc_max_interact_count;
    bool is_has_segment_crc_config;
    std::unordered_map<unsigned int, SegmentCrcPlatformConfig> segment_crc_config_map;
    std::unordered_map<unsigned int, std::unordered_map<std::string, std::vector<std::tuple<unsigned int, unsigned int, std::shared_ptr<SegmentCRCTree>>>>> platform_segment_crc_map;
    bool is_move_speed_check_open;
    bool is_move_speed_check_kick_player;
    bool is_move_speed_check_drag_player;
    bool is_scene_time_move_speed_check_open;
    bool is_scene_time_move_speed_check_kick_player;
    bool is_scene_time_move_speed_check_drag_player;
    int client_report_move_speed_over_limit_max_count;
    bool is_ability_config_hash_check_open;
    std::unordered_map<int, std::string> ability_config_hash_whitelist_map;
    bool is_enable_client_hash_debug;
    double unity_engine_timescale_limit;
    bool is_forbid_monster_disallowed_death;
    bool is_move_back_monster_on_forbid_death;
    bool is_revive_monster_on_forbid_death;
    bool is_use_server_override_map;
    bool is_use_server_dynamic_value;
    bool is_mouse_macro_check_open;
    std::map<unsigned int, EnvironmentErrorConfig> environment_config_map;
    SafeServerConfig safe_server_config;
    CheckQiandaoguaConfig check_qiandaogua_config;
    ClientTotalTickTimeConfig client_total_tick_time_config;
    ClientServerGlobalValueConfig client_server_global_value_config;
    StaminaCheckConfig stamina_check_config;
    PacketCostTimeExceedLimitConfig packet_cost_time_exceed_limit_config;
    RecvPacketFreqExceedLimitConfig recv_packet_freq_exceed_limit_config;
    SinglePacketFreqExceedLimitConfig single_packet_freq_exceed_limit_config;
    GadgetInteractBeyondCheckDistanceConfig gadget_interact_beyond_check_distance_config;
    LuaShellSecurityConfig lua_shell_security_config;
    AttackDamageReportConfig attack_damage_report_config;
};

SecurityConfig::SecurityConfig() {
    is_other_platform_need_check_anti_offline = 1;
    is_sec_channel_open = 0;
    is_checksum_version_not_found_forbid_login = 0;
    is_check_client_verion_hash_fail_forbid_login = 0;
    is_segment_crc_open = 0;
    is_checksum_version_not_found_segment_crc_default_open = 0;
    segment_crc_max_interact_count = 20;
    is_has_segment_crc_config = 0;
    is_move_speed_check_open = 1;
    is_move_speed_check_kick_player = 0;
    is_move_speed_check_drag_player = 1;
    is_scene_time_move_speed_check_open = 1;
    is_scene_time_move_speed_check_kick_player = 0;
    is_scene_time_move_speed_check_drag_player = 1;
    client_report_move_speed_over_limit_max_count = 100;
    is_ability_config_hash_check_open = 1;
    unity_engine_timescale_limit = 2.0;
    is_forbid_monster_disallowed_death = 1;
    is_move_back_monster_on_forbid_death = 1;
    is_revive_monster_on_forbid_death = 0;
    is_use_server_override_map = 0;
    is_use_server_dynamic_value = 0;
    is_mouse_macro_check_open = 1;
}

SecurityConfig::~SecurityConfig() {
    // Destructors for member objects
}

#endif // SECURITY_UTILS_H