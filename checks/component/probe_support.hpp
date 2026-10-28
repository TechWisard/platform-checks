#pragma once
#include <windows.h>
#include <ole2.h>
#include <oleauto.h>
#include <exception>
#include <utility>
#include <cstring>
#include <limits>
#include <string_view>

namespace native_contract_probe {

// Stages are source literals. COM/server descriptions and credential values are
// deliberately not retained in errors or diagnostics.
class Failure final : public std::exception {
public:
    Failure(const char* stage, HRESULT result) noexcept : stage_(stage), result_(result) {}
    const char* what() const noexcept override { return stage_; }
    HRESULT result() const noexcept { return result_; }
private:
    const char* stage_;
    HRESULT result_;
};

inline void require(HRESULT result, const char* stage) {
    if (FAILED(result)) {
        IErrorInfo* information{};
        // Native dual-interface calls may set Automation error information too.
        // Consume its reference, without retaining free-form/server text.
        GetErrorInfo(0, &information);
        if (information) information->Release();
        throw Failure(stage, result);
    }
}
inline HRESULT last_win32_error() noexcept {
    const DWORD error = GetLastError();
    return HRESULT_FROM_WIN32(error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error);
}

template<class T> class ComPtr final {
public:
    ComPtr() noexcept = default;
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) { reset(); value_ = std::exchange(other.value_, nullptr); }
        return *this;
    }
    T* get() const noexcept { return value_; }
    T* operator->() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != nullptr; }
    T** put() noexcept { reset(); return &value_; }
    void reset() noexcept { if (T* old = std::exchange(value_, nullptr)) old->Release(); }
    void attach(T* value) noexcept { reset(); value_ = value; }
    T* detach() noexcept { return std::exchange(value_, nullptr); }
    void copy_from(T* value) noexcept {
        if (value) value->AddRef();
        reset(); value_ = value;
    }
private:
    T* value_{};
};

template<class T> ComPtr<T> query(IUnknown* object, REFIID iid, const char* stage) {
    if (!object) throw Failure(stage, E_POINTER);
    ComPtr<T> result;
    require(object->QueryInterface(iid, reinterpret_cast<void**>(result.put())), stage);
    if (!result) throw Failure(stage, E_UNEXPECTED);
    return result;
}

inline void erase_bstr(BSTR text) noexcept {
    if (text) { SecureZeroMemory(text, SysStringByteLen(text)); SysFreeString(text); }
}
struct Value final {
    VARIANT value{};
    Value() noexcept { VariantInit(&value); }
    ~Value() { VariantClear(&value); }
    Value(const Value&) = delete;
    Value& operator=(const Value&) = delete;
};
struct String final {
    BSTR value{};
    explicit String(const wchar_t* text) : value(SysAllocString(text)) {
        if (!value) throw Failure("allocate_fixed_property_name", E_OUTOFMEMORY);
    }
    ~String() { erase_bstr(value); }
    String(const String&) = delete;
    String& operator=(const String&) = delete;
};
inline void check(bool condition, const char* stage, HRESULT result = E_UNEXPECTED) {
    if (!condition) throw Failure(stage, result);
}

} // namespace native_contract_probe
