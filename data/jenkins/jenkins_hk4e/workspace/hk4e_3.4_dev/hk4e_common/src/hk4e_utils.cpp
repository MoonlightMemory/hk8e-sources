#include <string>
#include <tuple>
#include <iostream>
#include <execinfo.h>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <utf8.h>
#include <common/tools/StringStream.h>
#include <common/milog/MiLogStream.h>
#include <opentracing/ext/tags.h>

class Hk4eUtils {
public:
    static int32_t checkStrUtf8Len(const std::string* content, uint32_t max_char);
    static int32_t checkStrUtf8DigitsNum(const std::string* content, uint32_t max_digits_num);
    static uint32_t formatMechanicusTag(uint32_t mechanicus_id, uint32_t difficult_level);
    static std::tuple<uint32_t, uint32_t> parseMechanicusTag(uint32_t mechanicus_tag);
    static void showTraceStack(const char* tag_string);
};

int32_t Hk4eUtils::checkStrUtf8Len(const std::string* content, uint32_t max_char) {
    if (content->empty()) {
        LOG_ERROR("content is empty!");
        return -1;
    }

    uint32_t char_cnt = 0;
    auto iter = content->begin();
    while (iter != content->end()) {
        utf8::uint32_t code_point = utf8::next(iter, content->end());
        if (code_point <= 0x1F) {
            LOG_ERROR("contain control char: {}", code_point);
            return 130;
        }
        ++char_cnt;
        if (char_cnt > max_char) {
            return 131;
        }
    }

    if (iter != content->end()) {
        LOG_ERROR("iter != content.end()");
        return 130;
    }

    return 0;
}

int32_t Hk4eUtils::checkStrUtf8DigitsNum(const std::string* content, uint32_t max_digits_num) {
    uint32_t total_digits_num = 0;
    auto iter = content->begin();
    while (iter != content->end()) {
        utf8::uint32_t cp = utf8::next(iter, content->end());
        if (iswdigit(cp)) {
            ++total_digits_num;
        }
        if (iter == content->end()) {
            common::milog::MiLogStream::create(
                &common::milog::MiLogDefault::default_log_obj_,
                1u,
                "src/hk4e_utils.cpp",
                "checkStrUtf8DigitsNum",
                156)
                << "utf8::next iter not advance!";
            return -1;
        }
    }

    if (total_digits_num > max_digits_num) {
        return -1;
    }

    if (iter != content->end()) {
        common::milog::MiLogStream::create(
            &common::milog::MiLogDefault::default_log_obj_,
            4u,
            "src/hk4e_utils.cpp",
            "checkStrUtf8DigitsNum",
            166)
            << "iter != content.end()";
        return -1;
    }

    return 0;
}

uint32_t Hk4eUtils::formatMechanicusTag(uint32_t mechanicus_id, uint32_t difficult_level) {
    return (mechanicus_id << 16) + difficult_level;
}

std::tuple<uint32_t, uint32_t> Hk4eUtils::parseMechanicusTag(uint32_t mechanicus_tag) {
    uint32_t mechanicus_id = mechanicus_tag >> 16;
    uint32_t difficult_level = mechanicus_tag & 0xFFFF;
    return std::make_tuple(mechanicus_id, difficult_level);
}

void Hk4eUtils::showTraceStack(const char* tag_string) {
    void* stack_array[30];
    size_t size = backtrace(stack_array, 30);
    char** stack_strings = backtrace_symbols(stack_array, size);

    if (stack_strings) {
        common::tools::StringStream<common::tools::FixedBuffer<4096>> ss;
        ss << tag_string << "\n";
        for (size_t i = 0; i < size; ++i) {
            ss << "[BACKTRACE]:" << stack_strings[i] << "\n";
        }
        free(stack_strings);

        common::milog::MiLogStream::create(
            &common::milog::MiLogDefault::default_log_obj_,
            1u,
            "src/hk4e_utils.cpp",
            "showTraceStack",
            208)
            << ss.str();
    }
}