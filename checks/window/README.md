# Independent native window calibration

A finite Win32 window paints eight fresh unpredictable colors. A real screen
capture must contain at least 80 step-four samples per color within tolerance
three, with all nine sampled roots belonging to the own window before and after
capture. Successful painting or an activation request alone does not pass.

This test has no RDP connection, account, device driver or input injection. It
closes its own window within 20 seconds; the wrapper bounds the process to
45 seconds and marks forced termination as unverified cleanup. Pixel data,
screenshots, window titles and native identifiers are not published.

Exit codes: 0 actual challenge/grid and cleanup passed; 1 failed; 2 cleanup
failed; 77 unavailable; wrapper 124 forced timeout. The session workflow still
collects the independent child-session result after a completed failed native
calibration, then explicitly fails the final calibration gate. Its failure is
not silently converted into a pass.
