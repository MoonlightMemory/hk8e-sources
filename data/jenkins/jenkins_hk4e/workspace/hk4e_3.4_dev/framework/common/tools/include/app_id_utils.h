#include <string>
#include "string_stream.h" // 假设这是自定义的 StringStream 实现

namespace common {
namespace tools {

class AppIdUtils {
public:
    // 获取 app_id 的数据部分
    static uint32_t getAppIdData(uint32_t app_id) {
        return app_id; // 直接返回 app_id，未进行额外处理
    }

    // 将 app_id 转换为字符串格式
    static std::string getAppIdStr(uint32_t app_id) {
        uint32_t app_id_data = getAppIdData(app_id); // 调用 getAppIdData 获取数据

        // 使用 StringStream 构建字符串
        StringStream stream;
        stream << (app_id_data & 0x3FF) << "."
               << ((app_id_data >> 2) & 0xF) << "."
               << ((app_id_data >> 14) & 0x3FFF) << "."
               << ((app_id_data >> 4) & 0xFF);

        return stream.str(); // 返回生成的字符串
    }
};

} // namespace tools
} // namespace common