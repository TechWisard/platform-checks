#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace {
constexpr wchar_t WindowClass[] = L"RuntimeProbeSyntheticWindow";
LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_CLOSE) { return DestroyWindow(window) ? 0 : 1; }
    if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(window, message, wparam, lparam);
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR arguments, int show) {
    if (arguments && *arguments) return 64;
    WNDCLASSEXW definition{};
    definition.cbSize = sizeof(definition); definition.hInstance = instance;
    definition.lpfnWndProc = procedure; definition.lpszClassName = WindowClass;
    definition.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassExW(&definition)) return 1;
    HWND window = CreateWindowExW(0, WindowClass, L"Runtime fixture", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 480, nullptr, nullptr, instance, nullptr);
    if (!window) return 2;
    ShowWindow(window, show); UpdateWindow(window);
    MSG message{};
    BOOL status{};
    while ((status = GetMessageW(&message, nullptr, 0, 0)) > 0) {
        TranslateMessage(&message); DispatchMessageW(&message);
    }
    const bool released = UnregisterClassW(WindowClass, instance) != FALSE;
    return status == 0 && released ? static_cast<int>(message.wParam) : 3;
}
