#pragma once
#include <windows.h>
#include <unknwn.h>
#include <cstdint>

// Independent test ABI. No credentials, connection methods, session API or
// product viewer UI crosses this boundary. Every call stays on the owner STA.
struct NativeHostSnapshot {
    std::uint32_t size, version;
    std::uint32_t parent_owned, sta_verified, client_site_attached;
    std::uint32_t in_place_active, ui_active, control_window_is_child;
    std::uint32_t activation_count, focus_calls, resize_calls;
    std::uint32_t key_down_translated, key_up_translated, other_key_translated;
    std::uint32_t translation_handled, translation_declined, translation_failed;
    std::uint32_t event_count, event_overflow, event_contract_failed;
    std::uint32_t connecting_sequence, connected_sequence, login_sequence, disconnected_sequence;
    std::uint32_t cleanup_started, sink_detached, unadvised, host_closed;
    std::uint32_t control_window_destroyed, references_released, ole_balanced;
    std::int32_t unadvise_hresult, host_close_hresult;
};
struct NativeHostEvent {
    std::uint32_t sequence, kind;
    std::int32_t code;
};
static_assert(sizeof(NativeHostSnapshot) == 33 * sizeof(std::uint32_t));
static_assert(sizeof(NativeHostEvent) == 12);

#define NATIVE_HOST_API extern "C" __declspec(dllexport) HRESULT WINAPI
NATIVE_HOST_API native_host_create(HWND parent, int width, int height, void** context, IUnknown** object);
NATIVE_HOST_API native_host_snapshot(void* context, NativeHostSnapshot* snapshot);
NATIVE_HOST_API native_host_event(void* context, unsigned index, NativeHostEvent* event);
NATIVE_HOST_API native_host_resize(void* context, int width, int height);
NATIVE_HOST_API native_host_focus(void* context);
NATIVE_HOST_API native_host_translate(void* context, HWND window, UINT message, WPARAM wparam, LPARAM lparam);
NATIVE_HOST_API native_host_begin_cleanup(void* context);
// Close checks the actual Connected property independently. Once consumed is
// set, no further call may use context even if a cleanup HRESULT is a failure.
NATIVE_HOST_API native_host_close(void* context, NativeHostSnapshot* snapshot, int* consumed);
// Failure-only detach: performs no COM call and retains native owners until
// this disposable process exits. It never establishes successful cleanup.
NATIVE_HOST_API native_host_abandon(void* context);
