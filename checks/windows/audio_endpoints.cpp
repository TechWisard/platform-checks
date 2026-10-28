#include "common.hpp"

#include <mmdeviceapi.h>

#include <memory>
#include <set>

namespace {

template<class T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { if (value_) value_->Release(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T* operator->() const noexcept { return value_; }
    T** put() noexcept { return &value_; }
private:
    T* value_ = nullptr;
};

class Apartment {
public:
    Apartment() : result_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {
        if (result_ != RPC_E_CHANGED_MODE) check::hresult(result_, "CoInitializeEx");
    }
    ~Apartment() { if (SUCCEEDED(result_)) CoUninitialize(); }
    Apartment(const Apartment&) = delete;
    Apartment& operator=(const Apartment&) = delete;
private:
    HRESULT result_;
};

struct TaskDeleter {
    void operator()(wchar_t* value) const noexcept { CoTaskMemFree(value); }
};

check::Counts query() {
    Apartment apartment;
    ComPtr<IMMDeviceEnumerator> enumerator;
    check::hresult(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(enumerator.put())),
        "CoCreateInstance(MMDeviceEnumerator)");
    std::set<std::string> identities;
    check::Counts counts{};
    for (const EDataFlow flow : {eRender, eCapture}) {
        ComPtr<IMMDeviceCollection> endpoints;
        check::hresult(enumerator->EnumAudioEndpoints(flow, DEVICE_STATE_ACTIVE, endpoints.put()), "EnumAudioEndpoints");
        UINT count = 0;
        check::hresult(endpoints->GetCount(&count), "IMMDeviceCollection::GetCount");
        check::require(count <= check::max_records, "Audio endpoint record bound exceeded");
        if (flow == eRender) counts.primary = count;
        else counts.secondary = count;
        for (UINT index = 0; index < count; ++index) {
            ComPtr<IMMDevice> endpoint;
            check::hresult(endpoints->Item(index, endpoint.put()), "IMMDeviceCollection::Item");
            wchar_t* allocated = nullptr;
            const HRESULT result = endpoint->GetId(&allocated);
            std::unique_ptr<wchar_t, TaskDeleter> native(allocated);
            check::hresult(result, "IMMDevice::GetId");
            check::require(native != nullptr, "Audio endpoint identity is null");
            auto identity = check::utf8(check::bounded_wide(native.get(), check::max_chars));
            check::require(!identity.empty() && identities.insert(std::move(identity)).second,
                "Empty or duplicate audio endpoint identity");
            DWORD state = 0;
            check::hresult(endpoint->GetState(&state), "IMMDevice::GetState");
            check::require(state == DEVICE_STATE_ACTIVE, "Active endpoint state changed during query");
            ComPtr<IMMEndpoint> endpoint_flow;
            check::hresult(endpoint->QueryInterface(__uuidof(IMMEndpoint),
                reinterpret_cast<void**>(endpoint_flow.put())), "QueryInterface(IMMEndpoint)");
            EDataFlow actual_flow = eAll;
            check::hresult(endpoint_flow->GetDataFlow(&actual_flow), "IMMEndpoint::GetDataFlow");
            check::require(actual_flow == flow, "Audio flow disagrees with collection");
        }
    }
    return counts;
}

} // namespace

int main() {
    return check::run("audio_endpoints", [] { check::repeat(query); });
}
