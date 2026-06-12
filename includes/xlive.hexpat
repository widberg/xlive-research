import std.core;

using XUID = u64;

fn all_eq(ref auto arr, auto val) {
    for (u64 i = 0, i < std::core::member_count(arr), i = i + 1) {
        if (arr[i] != val) {
            return false;
        }
    }
    return true;
};
