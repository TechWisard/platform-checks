// Standalone native visibility calibration. No RDP, accounts, hooks or input.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace {
constexpr wchar_t ClassName[] = L"IndependentNativeWindowCalibration";
constexpr UINT_PTR TimerId = 1;
constexpr ULONGLONG BudgetMs = 20000;
constexpr unsigned FullMask = 0x1ff;
struct State {
    HWND window{}; std::uintptr_t createdHandle{}; HINSTANCE instance{};
    std::array<COLORREF, 8> colors{}; std::array<HBRUSH, 8> brushes{};
    std::array<unsigned, 8> counts{}, closest{}; std::vector<std::uint32_t> pixels;
    DWORD session{}, sessionError{}, apiError{}, presentError{}, foregroundError{}, dpiError{};
    LONG rngStatus{}; int width{}, height{}, left{}, top{}, dpiMode{-1}, status{1}, stage{};
    UINT dpi{}; unsigned paintCount{}, captures{}, samples{}, beforeMask{}, afterMask{};
    ULONGLONG started{}, elapsed{}; ATOM registered{};
    bool sessionOk{}, dpiSet{}, present{}, foreground{}, timer{}, destroyRequested{}, destroyResult{};
    bool destroyed{}, quit{}, observed{}, captureOk{}, inside{}, visible{}, foregroundOwn{};
    bool gdiClean{true}, classClean{true}, windowClean{true};
} state;

template<class T> T Procedure(HMODULE module, const char* name) noexcept {
    FARPROC raw = GetProcAddress(module, name); T result{};
    static_assert(sizeof(result) == sizeof(raw));
    std::memcpy(&result, &raw, sizeof(result)); return result;
}
void ApiFailure(int stage) noexcept { state.stage = stage; state.apiError = GetLastError(); state.status = 77; }
void CloseOwnWindow() noexcept {
    if (!state.window) return;
    if (state.timer) { KillTimer(state.window, TimerId); state.timer = false; }
    state.destroyRequested = true;
    state.destroyResult = DestroyWindow(state.window) != FALSE;
    if (!state.destroyResult) { state.apiError = GetLastError(); state.status = 2; }
}
bool MakePalette() noexcept {
    for (std::size_t i = 0; i < state.colors.size(); ++i) {
        bool accepted = false;
        for (unsigned attempt = 0; attempt < 256 && !accepted; ++attempt) {
            std::array<UCHAR, 3> bytes{};
            state.rngStatus = BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (state.rngStatus < 0) return false;
            for (auto& value : bytes) value = static_cast<UCHAR>(24 + value % 208);
            if (static_cast<int>(*std::max_element(bytes.begin(), bytes.end())) -
                static_cast<int>(*std::min_element(bytes.begin(), bytes.end())) < 64) continue;
            accepted = true;
            for (std::size_t j = 0; j < i; ++j) {
                const int distance = std::max({std::abs(int(bytes[0]) - int(GetRValue(state.colors[j]))),
                    std::abs(int(bytes[1]) - int(GetGValue(state.colors[j]))), std::abs(int(bytes[2]) - int(GetBValue(state.colors[j])))});
                if (distance < 48) accepted = false;
            }
            if (accepted) state.colors[i] = RGB(bytes[0], bytes[1], bytes[2]);
        }
        if (!accepted) return false;
        state.brushes[i] = CreateSolidBrush(state.colors[i]);
        if (!state.brushes[i]) return false;
    }
    return true;
}
unsigned HitGrid(HWND own, POINT origin, int width, int height) noexcept {
    HWND ownRoot = GetAncestor(own, GA_ROOT);
    if (!ownRoot || ownRoot != own) return 0;
    unsigned mask = 0;
    for (int y = 0; y < 3; ++y) for (int x = 0; x < 3; ++x) {
        POINT point{origin.x + (2 * x + 1) * width / 6, origin.y + (2 * y + 1) * height / 6};
        HWND hit = WindowFromPoint(point);
        if (hit && GetAncestor(hit, GA_ROOT) == ownRoot) mask |= 1U << unsigned(y * 3 + x);
    }
    return mask;
}
struct CaptureObjects {
    HDC screen{}, memory{}; HBITMAP bitmap{}; HGDIOBJ previous{};
    ~CaptureObjects() {
        if (previous && memory) {
            HGDIOBJ restored = SelectObject(memory, previous);
            if (!restored || restored == HGDI_ERROR) state.gdiClean = false;
        }
        if (bitmap && !DeleteObject(bitmap)) state.gdiClean = false;
        if (memory && !DeleteDC(memory)) state.gdiClean = false;
        if (screen && ReleaseDC(nullptr, screen) != 1) state.gdiClean = false;
    }
};
void Capture() noexcept {
    ++state.captures; state.captureOk = false; state.counts.fill(0); state.closest.fill(255); state.samples = 0;
    state.beforeMask = 0; state.afterMask = 0; state.stage = 0; state.apiError = ERROR_SUCCESS;
    RECT client{}; POINT origin{};
    SetLastError(ERROR_SUCCESS);
    if (!GetClientRect(state.window, &client) || !ClientToScreen(state.window, &origin)) { ApiFailure(20); return; }
    if (client.right != state.width || client.bottom != state.height || client.left || client.top) { state.stage = 21; return; }
    state.left = origin.x; state.top = origin.y;
    const int vx = GetSystemMetrics(SM_XVIRTUALSCREEN), vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN), vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    state.inside = origin.x >= vx && origin.y >= vy &&
        static_cast<std::int64_t>(origin.x) + state.width <= static_cast<std::int64_t>(vx) + vw &&
        static_cast<std::int64_t>(origin.y) + state.height <= static_cast<std::int64_t>(vy) + vh;
    state.visible = IsWindowVisible(state.window) != FALSE;
    HWND foreground = GetForegroundWindow();
    state.foregroundOwn = foreground && GetAncestor(foreground, GA_ROOT) == state.window;
    state.beforeMask = HitGrid(state.window, origin, state.width, state.height);
    if (!state.inside) { state.stage = 22; return; }
    CaptureObjects objects;
    SetLastError(ERROR_SUCCESS);
    objects.screen = GetDC(nullptr);
    if (!objects.screen) { ApiFailure(23); return; }
    objects.memory = CreateCompatibleDC(objects.screen);
    if (!objects.memory) { ApiFailure(24); return; }
    objects.bitmap = CreateCompatibleBitmap(objects.screen, state.width, state.height);
    if (!objects.bitmap) { ApiFailure(25); return; }
    HGDIOBJ old = SelectObject(objects.memory, objects.bitmap);
    if (!old || old == HGDI_ERROR) { ApiFailure(26); return; }
    objects.previous = old;
    if (!BitBlt(objects.memory, 0, 0, state.width, state.height, objects.screen, origin.x, origin.y, SRCCOPY)) { ApiFailure(27); return; }
    old = SelectObject(objects.memory, objects.previous);
    if (!old || old == HGDI_ERROR) { ApiFailure(28); return; }
    objects.previous = nullptr; // GetDIBits requires the bitmap to be unselected.
    BITMAPINFO info{}; info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = state.width; info.bmiHeader.biHeight = -state.height;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32; info.bmiHeader.biCompression = BI_RGB;
    if (GetDIBits(objects.screen, objects.bitmap, 0, static_cast<UINT>(state.height), state.pixels.data(), &info, DIB_RGB_COLORS) != state.height) {
        ApiFailure(29); return;
    }
    state.afterMask = HitGrid(state.window, origin, state.width, state.height);
    for (int y = 0; y < state.height; y += 4) for (int x = 0; x < state.width; x += 4) {
        const auto pixel = state.pixels[static_cast<std::size_t>(y) * static_cast<std::size_t>(state.width) + static_cast<std::size_t>(x)];
        ++state.samples;
        for (std::size_t i = 0; i < state.colors.size(); ++i) {
            const unsigned distance = static_cast<unsigned>(std::max({
                std::abs(int((pixel >> 16) & 255U) - int(GetRValue(state.colors[i]))),
                std::abs(int((pixel >> 8) & 255U) - int(GetGValue(state.colors[i]))),
                std::abs(int(pixel & 255U) - int(GetBValue(state.colors[i])))}));
            state.closest[i] = std::min(state.closest[i], distance);
            if (distance <= 3) ++state.counts[i];
        }
    }
    SecureZeroMemory(state.pixels.data(), state.pixels.size() * sizeof(state.pixels[0]));
    state.captureOk = true;
    state.observed = state.paintCount > 0 && state.visible && state.beforeMask == FullMask && state.afterMask == FullMask &&
        std::all_of(state.counts.begin(), state.counts.end(), [](unsigned count) { return count >= 80; });
}
LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) noexcept {
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT paint{}; HDC dc = BeginPaint(window, &paint); RECT rect{};
        bool ok = dc && GetClientRect(window, &rect) && FillRect(dc, &rect, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        for (int i = 0; dc && i < 8; ++i) {
            const int column = i % 4, row = i / 4;
            RECT patch{column * state.width / 4 + 16, row * state.height / 2 + 16,
                (column + 1) * state.width / 4 - 16, (row + 1) * state.height / 2 - 16};
            if (!FillRect(dc, &patch, state.brushes[static_cast<std::size_t>(i)])) ok = false;
        }
        if (dc && !EndPaint(window, &paint)) ok = false;
        if (ok) ++state.paintCount; else ApiFailure(30);
        return 0;
    }
    case WM_TIMER:
        if (wparam == TimerId) {
            state.elapsed = GetTickCount64() - state.started;
            if (state.status == 77 || state.elapsed >= BudgetMs) { CloseOwnWindow(); return 0; }
            if (state.paintCount > 0) Capture();
            if (state.observed || state.status == 77) CloseOwnWindow();
        }
        return 0;
    case WM_CLOSE: CloseOwnWindow(); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    case WM_NCDESTROY: state.destroyed = true; state.window = nullptr; break;
    default: break;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}
bool Start() {
    state.closest.fill(255);
    state.sessionOk = ProcessIdToSessionId(GetCurrentProcessId(), &state.session) != FALSE;
    if (!state.sessionOk) { state.sessionError = GetLastError(); ApiFailure(1); return false; }
    if (state.session == 0) { state.stage = 13; state.status = 77; return false; }
    HMODULE user = GetModuleHandleW(L"user32.dll");
    const auto setDpi = Procedure<BOOL (WINAPI*)(HANDLE)>(user, "SetProcessDpiAwarenessContext");
    const auto context = Procedure<HANDLE (WINAPI*)()>(user, "GetThreadDpiAwarenessContext");
    const auto awareness = Procedure<int (WINAPI*)(HANDLE)>(user, "GetAwarenessFromDpiAwarenessContext");
    const auto windowDpi = Procedure<UINT (WINAPI*)(HWND)>(user, "GetDpiForWindow");
    if (!setDpi || !context || !awareness || !windowDpi) { ApiFailure(2); return false; }
    SetLastError(ERROR_SUCCESS);
    state.dpiSet = setDpi(reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-4))) != FALSE; // PER_MONITOR_AWARE_V2.
    state.dpiError = state.dpiSet ? ERROR_SUCCESS : GetLastError(); state.dpiMode = awareness(context());
    if (state.dpiMode != 2) { state.stage = 3; state.status = 77; return false; }
    MONITORINFO monitor{}; monitor.cbSize = sizeof(monitor);
    if (!GetMonitorInfoW(MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY), &monitor)) { ApiFailure(4); return false; }
    const LONG workWidth = monitor.rcWork.right - monitor.rcWork.left, workHeight = monitor.rcWork.bottom - monitor.rcWork.top;
    if (workWidth < 640 || workHeight < 360) { state.stage = 5; state.status = 77; return false; }
    state.width = static_cast<int>(std::min<LONG>(800, workWidth)); state.height = static_cast<int>(std::min<LONG>(480, workHeight));
    state.left = monitor.rcWork.left + (workWidth - state.width) / 2; state.top = monitor.rcWork.top + (workHeight - state.height) / 2;
    state.pixels.resize(static_cast<std::size_t>(state.width) * static_cast<std::size_t>(state.height));
    if (!MakePalette()) { ApiFailure(6); return false; }
    state.instance = GetModuleHandleW(nullptr);
    WNDCLASSEXW cls{}; cls.cbSize = sizeof(cls); cls.hInstance = state.instance;
    cls.lpfnWndProc = WindowProcedure; cls.lpszClassName = ClassName; cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    state.registered = RegisterClassExW(&cls);
    if (!state.registered) { ApiFailure(7); return false; }
    state.window = CreateWindowExW(0, ClassName, L"", WS_POPUP, state.left, state.top, state.width, state.height,
                                 nullptr, nullptr, state.instance, nullptr);
    if (!state.window) { ApiFailure(8); return false; }
    state.createdHandle = reinterpret_cast<std::uintptr_t>(state.window); state.dpi = windowDpi(state.window);
    if (!state.dpi) { ApiFailure(9); return false; }
    state.started = GetTickCount64(); SetLastError(ERROR_SUCCESS);
    state.present = SetWindowPos(state.window, HWND_TOPMOST, state.left, state.top, state.width, state.height,
                                 SWP_SHOWWINDOW | SWP_NOOWNERZORDER) != FALSE;
    state.presentError = state.present ? ERROR_SUCCESS : GetLastError();
    if (!state.present) { state.stage = 10; return false; }
    SetLastError(ERROR_SUCCESS); state.foreground = SetForegroundWindow(state.window) != FALSE;
    state.foregroundError = GetLastError(); // Diagnostic only: this API does not promise a last-error reason.
    state.timer = SetTimer(state.window, TimerId, 500, nullptr) != 0;
    if (!state.timer) { ApiFailure(11); return false; }
    return true;
}
void MessageLoop() noexcept {
    while (state.window && !state.quit) {
        state.elapsed = GetTickCount64() - state.started;
        if (state.elapsed >= BudgetMs) { CloseOwnWindow(); break; }
        const DWORD waitMs = static_cast<DWORD>(std::min<ULONGLONG>(250, BudgetMs - state.elapsed));
        const DWORD waited = MsgWaitForMultipleObjectsEx(0, nullptr, waitMs, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        if (waited == WAIT_FAILED) { ApiFailure(12); break; }
        MSG message{};
        for (unsigned count = 0; count < 64 && PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE); ++count) {
            if (message.message == WM_QUIT) { state.quit = true; break; }
            TranslateMessage(&message); DispatchMessageW(&message);
        }
    }
}
void Cleanup() noexcept {
    CloseOwnWindow();
    if (state.started) state.elapsed = GetTickCount64() - state.started;
    state.windowClean = !state.createdHandle || (state.destroyRequested && state.destroyResult && state.destroyed && !state.window &&
        !IsWindow(reinterpret_cast<HWND>(state.createdHandle)));
    if (state.registered) state.classClean = UnregisterClassW(ClassName, state.instance) != FALSE;
    for (HBRUSH brush : state.brushes) if (brush && !DeleteObject(brush)) state.gdiClean = false;
    if (!state.windowClean || !state.classClean || !state.gdiClean) state.status = 2;
    else if (state.observed && state.status != 77) state.status = 0;
    if (!state.pixels.empty()) SecureZeroMemory(state.pixels.data(), state.pixels.size() * sizeof(state.pixels[0]));
}
void Report() {
    const char* status = state.status == 0 ? "passed" : state.status == 77 ? "unavailable" : state.status == 2 ? "cleanup_failed" : "failed";
    std::cout << std::boolalpha << "{\"schema\":\"native-window-calibration/v1\",\"status\":\"" << status
      << "\",\"exit_code\":" << state.status << ",\"stage\":" << state.stage << ",\"api_error\":" << state.apiError
      << ",\"session_query_ok\":" << state.sessionOk << ",\"session_id\":" << state.session << ",\"session_error\":" << state.sessionError
      << ",\"rng_status\":" << state.rngStatus << ",\"dpi_set\":" << state.dpiSet
      << ",\"dpi_error\":" << state.dpiError << ",\"dpi_awareness\":" << state.dpiMode << ",\"window_dpi\":" << state.dpi
      << ",\"present_return\":" << state.present << ",\"present_error\":" << state.presentError
      << ",\"foreground_request_return\":" << state.foreground << ",\"foreground_last_error_observed\":" << state.foregroundError
      << ",\"foreground_root_is_own\":" << state.foregroundOwn << ",\"window_visible\":" << state.visible
      << ",\"client_origin\":[" << state.left << ',' << state.top << "],\"client_size\":[" << state.width << ',' << state.height
      << "],\"inside_virtual_screen\":" << state.inside << ",\"own_root_mask_before\":" << state.beforeMask
      << ",\"own_root_mask_after\":" << state.afterMask << ",\"paint_count\":" << state.paintCount << ",\"capture_count\":" << state.captures
      << ",\"capture_ok\":" << state.captureOk << ",\"sample_count\":" << state.samples << ",\"counts_within3\":[";
    for (std::size_t i = 0; i < 8; ++i) std::cout << (i ? "," : "") << state.counts[i];
    std::cout << "],\"closest_color_distances\":[";
    for (std::size_t i = 0; i < 8; ++i) std::cout << (i ? "," : "") << state.closest[i];
    std::cout << "],\"observed_challenge_and_grid\":" << state.observed << ",\"elapsed_ms\":" << state.elapsed
      << ",\"destroy_return\":" << state.destroyResult << ",\"own_window_cleanup\":" << state.windowClean
      << ",\"class_cleanup\":" << state.classClean << ",\"gdi_cleanup\":" << state.gdiClean << "}\n";
}
} // namespace
int main() {
    try { if (Start()) MessageLoop(); }
    catch (...) { state.stage = 99; state.status = 77; }
    Cleanup(); Report(); return state.status;
}
