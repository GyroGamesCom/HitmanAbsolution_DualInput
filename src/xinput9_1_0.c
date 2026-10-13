/*
 * xinput9_1_0.dll proxy for Hitman Absolution (Steam, HMA.exe x86, fixed base 0x400000)
 * - "dual input": gamepad stays the active device, mouse (Steam gyro-as-mouse) drives the
 * camera through the game's own mouse path. See re/FINDINGS_input.md.
 *
 * HMA.exe imports XINPUT9_1_0.dll BY NAME (XInputGetState / XInputSetState). The exports
 * are plain pass-throughs to the real SysWOW64 DLL (Steam Input may detour them); the exe's
 * IAT slot for XInputGetState is repointed at MixedGetState, which calls the export.
 *
 * NO writes to the exe's .text/.rdata: HMA.exe has anti-tamper code checksums (0xDC4900; a modified
 * byte makes the game crash right after start, see re/FINDINGS_input.md "Anti-tamper"). The only write
 * into the exe image is the IAT slot above. Everything else is done by vptr swapping on objects that
 * live in .data / heap, using vtable copies kept inside this DLL (the copies are written completely
 * before the vptr is published; the original vtables are only read):
 *   PatchCamera  the static ZInputDeviceManagerWindows (0x122EE10, vptr 0xEE7B9C) gets a vtable copy whose
 *                slot 10 (+0x28, GetActiveDevice) is HookGetActiveDevice: it returns the MOUSE device to the
 *                camera integrators (call-site whitelist by return address) on frames where the mouse
 *                moved, so they take their native linear mouse branch. Re-installed if the vptr reverts.
 *   PatchSwitch  mouse (and keyboard with PadLock=1) device objects get a vtable copy whose slot 1 (GetType)
 *                is HookGetType: it returns 4 (virtual) only to the active-device switch (return address
 *                0x7F7F11), so the mouse never becomes the active device and the game keeps pad glyphs.
 * A maintenance pass (install thread, then about once per second from the XInput wrapper) handles objects
 * that are created late or recreated.
 * IDirectInputDevice8A::GetDeviceState (vtable 9) is hooked for cbData==0x14 (DIMOUSESTATE2).
 */
#define WIN32_LEAN_AND_MEAN
#define DIRECTINPUT_VERSION 0x0800
#include <windows.h>
#include <xinput.h>
#include <dinput.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdarg.h>

typedef DWORD (WINAPI *PFN_GetState)(DWORD, XINPUT_STATE *);
typedef DWORD (WINAPI *PFN_SetState)(DWORD, XINPUT_VIBRATION *);
typedef DWORD (WINAPI *PFN_GetCaps)(DWORD, DWORD, XINPUT_CAPABILITIES *);
typedef DWORD (WINAPI *PFN_Guids)(DWORD, LPWSTR, UINT *, LPWSTR, UINT *);

static HMODULE g_real, g_self;
static char g_log[MAX_PATH];
static volatile LONG g_iatOk;        /* exe IAT slot of XInputGetState repointed at MixedGetState */

/* ---- settings (xinput_mouse.ini next to the DLL) ---- */
static char  g_ini[MAX_PATH];
static int   g_enabled = 1, g_invertY, g_menuMouse, g_useFlags = 1, g_useInp = 1, g_useFE = 1, g_usePause = 1;
static int   g_hold, g_gyroAim = 1, g_padLock, g_toggleVk, g_logLevel = 1, g_natLocked = 1;
static int   g_doP1 = 1, g_doP2 = 1, g_doDI = 1, g_doIat = 1, g_crashLog = 1;
static float g_sens = 1.0f, g_override = 0.25f, g_natTauMs, g_natMaxSpeed = 1500.0f, g_natFrameMs = 16.667f;
static FILETIME g_iniTime;

static void Log(const char *fmt, ...)
{
    FILE *f;
    va_list ap;
    if (!g_log[0] || !(f = fopen(g_log, "a"))) return;
    fprintf(f, "%lu ms: ", GetTickCount());
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static PFN_GetState p_GetState;
static PFN_SetState p_SetState;
static PFN_GetCaps  p_GetCaps;
static PFN_Guids    p_Guids;
static PFN_GetState p_PadState;      /* our export as seen through a possible Steam detour */

static volatile LONG g_natReset;

static void StampIni(void)
{
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (g_ini[0] && GetFileAttributesExA(g_ini, GetFileExInfoStandard, &fa)) g_iniTime = fa.ftLastWriteTime;
}

/* initial=0 on hot reload: Enabled only overrides the runtime toggle when its value in the file changed;
   PadLock (patch) is read at startup only */
static void ReadSettings(int initial)
{
    char buf[64];
    static int prevEn = 1;
    int en;
#define GETF(key, var, def) do { GetPrivateProfileStringA("Mouse", key, def, buf, sizeof buf, g_ini); var = (float)atof(buf); } while (0)
#define GETI(key, var, def) var = GetPrivateProfileIntA("Mouse", key, def, g_ini)
    GETF("NativeSensitivity", g_sens, "1.0");
    GETF("StickOverride", g_override, "0.25");
    GETF("NativeSmoothingMs", g_natTauMs, "0");
    GETF("NativeSmoothingMaxSpeed", g_natMaxSpeed, "1500");
    GETF("NativeFrameMs", g_natFrameMs, "16.667");
    GETI("NativeFrameLocked", g_natLocked, 1); g_natLocked = g_natLocked != 0;
    GETI("InvertY", g_invertY, 0);
    GETI("MouseFrameHold", g_hold, 0);
    GETI("GyroAimAssist", g_gyroAim, 1);
    GETI("MenuMouse", g_menuMouse, 0);
    GETI("UseMenuFlags", g_useFlags, 1);
    GETI("UseInputEnabled", g_useInp, 1);
    GETI("UseFrontEndFlag", g_useFE, 1);
    GETI("UsePauseFlag", g_usePause, 1);
    GETI("ToggleKey", g_toggleVk, 0);
    GETI("LogLevel", g_logLevel, 1);
    if (initial) {
        GETI("PadLock", g_padLock, 0);
        GETI("PatchSwitch", g_doP1, 1);
        GETI("PatchCamera", g_doP2, 1);
        GETI("HookMouse", g_doDI, 1);
        GETI("HookXInput", g_doIat, 1);
        GETI("CrashLog", g_crashLog, 1);
    }
    GETI("Enabled", en, 1);
#undef GETF
#undef GETI
    if (initial || en != prevEn) g_enabled = en;
    prevEn = en;
    if (g_sens < 0.01f) g_sens = 0.01f;
    if (g_sens > 20.0f) g_sens = 20.0f;
    if (g_override < 0.0f) g_override = 0.0f;
    if (g_natTauMs < 0.0f) g_natTauMs = 0.0f;
    if (g_natTauMs > 500.0f) g_natTauMs = 500.0f;
    if (g_natMaxSpeed < 0.0f) g_natMaxSpeed = 0.0f;
    if (g_natFrameMs < 4.0f) g_natFrameMs = 4.0f;
    if (g_natFrameMs > 50.0f) g_natFrameMs = 50.0f;
    if (g_hold < 0) g_hold = 0;
    InterlockedExchange(&g_natReset, 1);
    StampIni();
}

static void SettingsSummary(char *out, size_t n)
{
    _snprintf(out, n, "enabled=%d sens=%.3f invertY=%d override=%.2f smooth=%.1fms/%.0f locked=%d/%.3fms hold=%d padLock=%d gyroAim=%d menuMouse=%d useFlags=%d(inp=%d fe=%d pause=%d) toggleKey=%d loglevel=%d",
        g_enabled, g_sens, g_invertY, g_override, g_natTauMs, g_natMaxSpeed, g_natLocked, g_natFrameMs, g_hold, g_padLock,
        g_gyroAim, g_menuMouse, g_useFlags, g_useInp, g_useFE, g_usePause, g_toggleVk, g_logLevel);
    out[n - 1] = 0;
}

static void LoadSettings(HMODULE self)
{
    char *slash;
    GetModuleFileNameA(self, g_ini, MAX_PATH);
    slash = strrchr(g_ini, '\\');
    if (!slash) { g_ini[0] = 0; return; }
    strcpy(slash + 1, "xinput_mouse.ini");
    ReadSettings(1);
}

static void CheckReload(void)
{
    static DWORD last;
    WIN32_FILE_ATTRIBUTE_DATA fa;
    DWORD now = GetTickCount();
    if (!g_ini[0] || now - last < 1000) return;
    last = now;
    if (!GetFileAttributesExA(g_ini, GetFileExInfoStandard, &fa)) return;
    if (CompareFileTime(&fa.ftLastWriteTime, &g_iniTime) == 0) return;
    ReadSettings(0);
    { char sum[400]; SettingsSummary(sum, sizeof sum); Log("settings reloaded: %s", sum); }
}

/* ---- safe reads of game memory ---- */
static int Rd(DWORD va, void *out, size_t n)
{
    __try { memcpy(out, (const void *)va, n); } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 1;
}
static int RdU32(DWORD va, DWORD *v) { *v = 0; return Rd(va, v, 4); }
static int RdU8(DWORD va, BYTE *v)   { *v = 0; return Rd(va, v, 1); }

static void HexStr(const BYTE *b, size_t n, char *out)
{
    size_t i;
    for (i = 0; i < n; i++) sprintf(out + i * 3, "%02X ", b[i]);
    out[n * 3] = 0;
}

/* ---- game state ---- */
#define A_ACTIVE   0x122F7ACu
#define A_DEVLIST  0x122EE14u
#define A_DEVCOUNT 0x122EE94u
#define A_HITMAN   0x1221358u
#define A_FE       0x1161C7Cu
#define A_PAUSE    0x1161C7Du

static volatile LONG g_mouseFrame;
static int  g_holdLeft;
static LONG g_cntPassed, g_cntMenuZero, g_cntStick, g_cntFrames, g_cntGds, g_cntOff;
static LONG g_hookCalls;
static LONG g_cntType4;                 /* tentative decls; defined with the vptr code below */
static volatile LONG g_mgrOk;
static int g_ndvt;

/* gameplay predicate: IM = *(*(0x1221358)+0xA30); IM && IM[+0xA8] && !b(0x1161C7C) && !b(0x1161C7D).
   Every raw value is logged on change. */
static int Gameplay(void)
{
    DWORD H = 0, IM = 0;
    BYTE a8 = 0, fe = 0, pa = 0;
    int gp;
    static DWORD lIM = 0xFFFFFFFF, lH = 0xFFFFFFFF;
    static int lA8 = -1, lFE = -1, lPA = -1, lGP = -1;
    RdU32(A_HITMAN, &H);
    if (H) RdU32(H + 0xA30, &IM);
    if (IM) RdU8(IM + 0xA8, &a8);
    RdU8(A_FE, &fe);
    RdU8(A_PAUSE, &pa);
    if (g_logLevel >= 1) {
        if (H != lH || IM != lIM) { Log("flags: H=0x%08lX IM=0x%08lX", H, IM); lH = H; lIM = IM; }
        if (a8 != lA8) { Log("flags: IM+0xA8 (input enabled) = %u", a8); lA8 = a8; }
        if (fe != lFE) { Log("flags: 0x1161C7C (front-end) = %u", fe); lFE = fe; }
        if (pa != lPA) { Log("flags: 0x1161C7D (pause) = %u", pa); lPA = pa; }
    }
    gp = 1;
    if (g_useFlags) {
        if (g_useInp && !(IM && a8)) gp = 0;
        if (g_useFE && fe) gp = 0;
        if (g_usePause && pa) gp = 0;
    }
    if (gp != lGP) { if (g_logLevel >= 1) Log("gameplay: %s", gp ? "YES (mouse look allowed)" : "NO (menu/cutscene/pause)"); lGP = gp; }
    return gp;
}


/* ---- crash logger: first-chance faults (the game exits silently through its own handler) ---- */
static volatile LONG g_vehCount;
static LONG CALLBACK CrashVeh(EXCEPTION_POINTERS *ep)
{
    DWORD c = ep->ExceptionRecord->ExceptionCode;
    CONTEXT *x = ep->ContextRecord;
    HMODULE m = NULL;
    char mod[MAX_PATH] = "?";
    if (c != EXCEPTION_ACCESS_VIOLATION && c != EXCEPTION_ILLEGAL_INSTRUCTION && c != EXCEPTION_PRIV_INSTRUCTION &&
        c != EXCEPTION_STACK_OVERFLOW && c != EXCEPTION_INT_DIVIDE_BY_ZERO && c != 0xC0000409)
        return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedIncrement(&g_vehCount) > 20) return EXCEPTION_CONTINUE_SEARCH;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)ep->ExceptionRecord->ExceptionAddress, &m) && m)
        GetModuleFileNameA(m, mod, MAX_PATH);
    Log("EXCEPTION 0x%08lX at %p (%s base %p) info %p/%p thread %lu | eax=%08lX ebx=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX ebp=%08lX esp=%08lX",
        c, ep->ExceptionRecord->ExceptionAddress, mod, m,
        (void *)ep->ExceptionRecord->ExceptionInformation[0], (void *)ep->ExceptionRecord->ExceptionInformation[1],
        GetCurrentThreadId(), x->Eax, x->Ebx, x->Ecx, x->Edx, x->Esi, x->Edi, x->Ebp, x->Esp);
    {   /* a few stack dwords that look like code return addresses */
        DWORD *sp = (DWORD *)x->Esp; int i, k = 0; char b[300]; int p = 0;
        for (i = 0; i < 256 && k < 12; i++) {
            DWORD v;
            if (!RdU32((DWORD)(UINT_PTR)(sp + i), &v)) break;
            if ((v >= 0x401000 && v < 0xE2B000) || (v >= (DWORD)(UINT_PTR)g_self && v < (DWORD)(UINT_PTR)g_self + 0x40000)) {
                p += _snprintf(b + p, sizeof b - p - 1, "%08lX ", v); k++;
            }
        }
        b[p] = 0;
        Log("  stack code refs: %s", b);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---- pad state seen through XInputGetState ---- */
static volatile LONG g_conn[4];
static volatile short g_rx[4], g_ry[4];

static int PadUser(void)
{
    int i;
    for (i = 0; i < 4; i++) if (g_conn[i]) return i;
    return -1;
}

static int StickBusy(void)
{
    int u = PadUser();
    float sx, sy;
    if (u < 0) return 0;
    sx = g_rx[u] / 32767.0f; sy = g_ry[u] / 32767.0f;
    return sqrtf(sx * sx + sy * sy) > g_override;
}

/* ---- camera whitelist for HookGetActiveDevice ---- */
#define NWL 10
static struct { DWORD ra; int on; LONG hits; } g_wl[NWL] = {
    { 0x54B760 }, { 0x4C24C1 }, { 0x4C2539 }, { 0x4C2634 }, { 0x4C27F3 },
    { 0x74B07A }, { 0x74B2DB }, { 0x85D1AE }, { 0x85D2C9 },
    { 0x674C34 }     /* aim-assist flag site: whitelisted only when GyroAimAssist=0 */
};
static void *g_mouseDev;
static int   g_mouseIdx = -1;

static void *FindMouse(char *mgr)
{
    int n = *(int *)(mgr + 0x84), i;
    void **l = (void **)(mgr + 4);
    if (n > 32) n = 32;
    if (g_mouseIdx >= 0 && g_mouseIdx < n && l[g_mouseIdx] == g_mouseDev) return g_mouseDev;
    for (i = 0; i < n; i++) {
        char *d = (char *)l[i];
        if (d && *(int *)(d + 0x78) == 0) { g_mouseDev = d; g_mouseIdx = i; return d; }
    }
    return NULL;
}

/* thiscall getter without stack args: ecx = manager */
static void *__fastcall HookGetActiveDevice(void *mgr)
{
    void *real = *(void **)((char *)mgr + 0x99C);
    g_hookCalls++;
    if (g_mouseFrame) {
        DWORD ra = (DWORD)(UINT_PTR)_ReturnAddress();
        int i;
        for (i = 0; i < NWL; i++) {
            if (g_wl[i].ra != ra) continue;
            if (g_wl[i].on && !(i == NWL - 1 && g_gyroAim)) {
                void *m = FindMouse((char *)mgr);
                g_wl[i].hits++;
                if (m) return m;
            }
            break;
        }
    }
    return real;
}

/* ---- native-mode smoothing: distance-preserving exponential release (ported from the P2 proxy) ---- */
typedef struct { double pending, carry, speed, accIn; } NATAX;
static NATAX g_nat[2];
static double g_natPollT, g_natPollDt;
static int    g_natDupNow;
static float  g_remX, g_remY;
static LARGE_INTEGER g_freq;

static double QpcNow(void)
{
    LARGE_INTEGER q;
    if (!g_freq.QuadPart) QueryPerformanceFrequency(&g_freq);
    QueryPerformanceCounter(&q);
    return (double)q.QuadPart / (double)g_freq.QuadPart;
}

static void NatCheckReset(void)
{
    if (InterlockedExchange(&g_natReset, 0)) {
        memset(g_nat, 0, sizeof g_nat); g_natPollT = g_natPollDt = 0.0; g_natDupNow = 0; g_remX = g_remY = 0.0f;
    }
}

static void NatPoll(double t)
{
    g_natDupNow = 0;
    g_natPollDt = g_natPollT > 0.0 ? t - g_natPollT : 0.0;
    if (!g_natLocked) { g_natPollT = t; return; }
    if (g_natPollT > 0.0 && g_natPollDt < 0.001) { g_natDupNow = 1; return; }   /* second poll in the same frame */
    g_natPollT = t;
}

static LONG NatAxis(int a, LONG in)
{
    NATAX *n = &g_nat[a];
    double dt, tau, f, out, total;
    LONG emit;
    n->pending += (double)in;
    n->accIn += (double)in;
    if (g_natDupNow) return 0;
    dt = g_natLocked ? g_natFrameMs / 1000.0 : (g_natPollDt > 0.0 ? g_natPollDt : 0.016);
    if (!g_natLocked) { if (dt < 0.001) dt = 0.001; if (dt > 0.1) dt = 0.1; }
    tau = g_natTauMs / 1000.0;
    if (g_natMaxSpeed > 0.0f) {
        double k;
        n->speed += ((fabs(n->accIn) / dt) - n->speed) * (1.0 - exp(-dt / 0.05));
        k = (n->speed - g_natMaxSpeed) / g_natMaxSpeed;
        if (k < 0.0) k = 0.0;
        if (k > 1.0) k = 1.0;
        tau *= (1.0 - k);
    }
    n->accIn = 0.0;
    f = tau > 1e-5 ? 1.0 - exp(-dt / tau) : 1.0;
    out = n->pending * f;
    total = out + n->carry;
    emit = (LONG)total;
    n->carry = total - (double)emit;
    n->pending -= out;
    return emit;
}

static LONG ScaleAxis(LONG v, float *rem)
{
    float f;
    LONG r;
    if (g_sens == 1.0f) return v;
    f = (float)v * g_sens + *rem;
    r = (LONG)f;
    *rem = f - (float)r;
    return r;
}

/* ---- mouse GetDeviceState processing ---- */
static void ClearFrame(void) { g_holdLeft = 0; g_mouseFrame = 0; }

static void ProcessMouse(LONG *xy)
{
    LONG ox = xy[0], oy = xy[1], x, y;
    if (!g_enabled || PadUser() < 0) {          /* mod off / no pad: untouched, camera uses the normal path */
        ClearFrame(); InterlockedExchange(&g_natReset, 1);
        g_cntOff++;
        return;
    }
    if (!Gameplay()) {
        if (!g_menuMouse) { if (ox || oy) g_cntMenuZero++; xy[0] = xy[1] = 0; }
        ClearFrame(); InterlockedExchange(&g_natReset, 1);
        return;
    }
    if (StickBusy()) {                          /* real right stick wins; drop pending motion */
        if (ox || oy) g_cntStick++;
        xy[0] = xy[1] = 0;
        ClearFrame(); InterlockedExchange(&g_natReset, 1);
        return;
    }
    NatCheckReset();
    x = ScaleAxis(ox, &g_remX);
    y = ScaleAxis(oy, &g_remY);
    if (g_invertY) y = -y;
    if (g_natTauMs > 0.0f) {
        NatPoll(QpcNow());
        x = NatAxis(0, x);
        y = NatAxis(1, y);
    }
    xy[0] = x; xy[1] = y;
    if (ox || oy || x || y) g_cntPassed++;
    if (x || y) { g_holdLeft = g_hold; g_mouseFrame = 1; g_cntFrames++; }
    else if (g_holdLeft > 0) { g_holdLeft--; g_mouseFrame = 1; g_cntFrames++; }
    else g_mouseFrame = 0;
}

typedef HRESULT (STDMETHODCALLTYPE *PFN_GDS)(IDirectInputDevice8A *, DWORD, LPVOID);
static PFN_GDS o_GDS;
static volatile LONG g_diHooked, g_firstGds;

static HRESULT STDMETHODCALLTYPE Hook_GetDeviceState(IDirectInputDevice8A *self, DWORD cb, LPVOID data)
{
    void *ra = _ReturnAddress();
    HRESULT hr = o_GDS(self, cb, data);
    if (FAILED(hr) || !data || cb != 0x14) return hr;     /* DIMOUSESTATE2: lX,lY,lZ,buttons[8] */
    g_cntGds++;
    if (!InterlockedExchange(&g_firstGds, 1) && g_logLevel >= 1)
        Log("mouse GetDeviceState first call: device %p cbData=%lu from %p (coop level is not queryable; game uses 5 or 0xA)", self, cb, ra);
    ProcessMouse((LONG *)data);
    return hr;
}

/* ---- XInput wrapper: pad tracking, hot reload, hotkey, diagnostics ---- */
static void HandleHotkeys(void)
{
    static int prev;
    HWND fg = GetForegroundWindow();
    DWORD pid = 0;
    int down;
    if (fg) GetWindowThreadProcessId(fg, &pid);
    down = pid == GetCurrentProcessId() && g_toggleVk && (GetAsyncKeyState(g_toggleVk) & 0x8000) != 0;
    if (down && !prev) {
        g_enabled = !g_enabled;
        ClearFrame(); InterlockedExchange(&g_natReset, 1);
        if (g_logLevel >= 1) Log("hotkey: mod %s", g_enabled ? "ON" : "OFF");
    }
    prev = down;
}

static void LogActiveType(void)
{
    static DWORD lDev = 0xFFFFFFFF;
    static int lType = -2;
    DWORD dev = 0, ty = 0;
    int t = -1;
    RdU32(A_ACTIVE, &dev);
    if (dev && RdU32(dev + 0x78, &ty)) t = (int)ty;
    if (t != lType || dev != lDev) {
        Log("active device: 0x%08lX type=%d (0 mouse, 1 keyboard, 2 pad, 4 virtual)", dev, t);
        lType = t; lDev = dev;
    }
}

static float PadDeadZone(void)
{
    DWORD n = 0, i, d = 0;
    float f = -1.0f;
    RdU32(A_DEVCOUNT, &n);
    if (n > 32) n = 32;
    for (i = 0; i < n; i++) {
        DWORD ty = 0xFF;
        if (RdU32(A_DEVLIST + i * 4, &d) && d && RdU32(d + 0x78, &ty) && ty == 2) { Rd(d + 0x80, &f, 4); break; }
    }
    return f;
}

static void Summary(void)
{
    static DWORD last;
    DWORD now = GetTickCount(), act = 0, ty = 0, H = 0, IM = 0;
    int i, p = 0;
    float imc = 0, im8 = 0;
    char hits[200];
    if (g_logLevel < 2 || now - last < 5000) return;
    last = now;
    hits[0] = 0;
    RdU32(A_ACTIVE, &act); if (act) RdU32(act + 0x78, &ty);
    RdU32(A_HITMAN, &H); if (H) RdU32(H + 0xA30, &IM);
    if (IM) { Rd(IM + 0xC, &imc, 4); Rd(IM + 0x8, &im8, 4); }
    for (i = 0; i < NWL; i++) p += _snprintf(hits + p, sizeof hits - p - 1, "%X:%ld%s ", g_wl[i].ra, g_wl[i].hits, g_wl[i].on ? "" : "(off)");
    Log("summary: gds=%ld passed=%ld off=%ld menuZeroed=%ld stickStripped=%ld mouseFrames=%ld frame=%ld | hookCalls=%ld type4=%ld hits[%s] | mgrHook=%ld devSwapped=%d | activeType=%lu IM+0xC=%.4f IM+0x8=%.4f padDeadZone=%.3f | pad user=%d",
        g_cntGds, g_cntPassed, g_cntOff, g_cntMenuZero, g_cntStick, g_cntFrames, g_mouseFrame, g_hookCalls, g_cntType4, hits, g_mgrOk, g_ndvt,
        ty, imc, im8, PadDeadZone(), PadUser());
}

static void MaintainTick(void);

static DWORD WINAPI MixedGetState(DWORD user, XINPUT_STATE *st)
{
    DWORD r = (g_iatOk && p_PadState) ? p_PadState(user, st) : p_GetState ? p_GetState(user, st) : ERROR_DEVICE_NOT_CONNECTED;
    if (user < 4) {
        LONG ok = (r == ERROR_SUCCESS && st) ? 1 : 0;
        static LONG seen[4] = { -1, -1, -1, -1 };
        if (g_logLevel >= 1 && seen[user] != ok) {
            Log("pad user %lu: %s (rc=%lu)", user, ok ? "CONNECTED" : "not connected", r);
            seen[user] = ok;
        }
        g_conn[user] = ok;
        if (ok) { g_rx[user] = st->Gamepad.sThumbRX; g_ry[user] = st->Gamepad.sThumbRY; }
        else { g_rx[user] = g_ry[user] = 0; }
    }
    CheckReload();
    MaintainTick();
    HandleHotkeys();
    if (g_logLevel >= 1) LogActiveType();
    Summary();
    return r;
}

/* ---- exports (ordinals as in the real xinput9_1_0.dll) ---- */
DWORD WINAPI XInputGetState(DWORD user, XINPUT_STATE *st)
{
    if (g_iatOk) return p_GetState ? p_GetState(user, st) : ERROR_DEVICE_NOT_CONNECTED;   /* exe goes through the wrapper */
    return MixedGetState(user, st);
}

DWORD WINAPI XInputSetState(DWORD user, XINPUT_VIBRATION *v)
{
    return p_SetState ? p_SetState(user, v) : ERROR_DEVICE_NOT_CONNECTED;
}

DWORD WINAPI XInputGetCapabilities(DWORD user, DWORD flags, XINPUT_CAPABILITIES *c)
{
    return p_GetCaps ? p_GetCaps(user, flags, c) : ERROR_DEVICE_NOT_CONNECTED;
}

DWORD WINAPI XInputGetDSoundAudioDeviceGuids(DWORD user, LPWSTR a, UINT *an, LPWSTR b, UINT *bn)
{
    return p_Guids ? p_Guids(user, a, an, b, bn) : ERROR_DEVICE_NOT_CONNECTED;
}

/* ---- vptr swapping (no writes to the exe's .text/.rdata: anti-tamper checksums, see FINDINGS) ----
   Each vtable is copied ([-1] RTTI locator + VT_SLOTS entries) into a buffer inside this DLL, one slot is
   replaced, and only then the vptr of the live object (in .data / heap) is repointed at the copy. */
#define VT_SLOTS   64
#define A_MGR      0x122EE10u
#define VT_MGR     0x00EE7B9Cu
#define MGR_SLOT   10            /* vt+0x28 GetActiveDevice */
#define DEV_SLOT   1             /* vt+0x04 GetType */
#define RA_SWITCH  0x7F7F11u

static DWORD g_mgrVt[VT_SLOTS + 1];          /* [0] = RTTI locator, [1..] = slots; vptr -> &g_mgrVt[1] */
static int   g_mgrBuilt, g_mgrFailed, g_mgrEver;
static volatile LONG g_mgrOk;

typedef struct { DWORD orig; int ok; DWORD buf[VT_SLOTS + 1]; } DEVVT;
static DEVVT g_dvt[4];
static int   g_ndvt, g_swCtx;                /* g_swCtx: 0 unchecked, 1 context ok, -1 mismatch (switch fix off) */
static volatile LONG g_mouseSwapped;
static LONG  g_cntType4;

/* int GetType(): called by the active-device switch at 0x7F7F11 -> report "virtual" (4) so the device is skipped */
static int __fastcall HookGetType(void *dev)
{
    if ((DWORD)(UINT_PTR)_ReturnAddress() == RA_SWITCH) { g_cntType4++; return 4; }
    return *(int *)((char *)dev + 0x78);
}

/* site ra must be preceded by a call and followed by the active-device type test */
static int WlSiteOk(DWORD ra, BYTE *got)
{
    static const BYTE follow[12] = { 0x8B,0x10,0x8B,0xC8,0x8B,0x42,0x04,0xFF,0xD0,0x83,0xF8,0x02 };
    BYTE b[6 + 12];
    int call;
    if (!Rd(ra - 6, b, sizeof b)) return 0;
    memcpy(got, b, sizeof b);
    call = (b[4] == 0xFF && (b[5] & 0xF8) == 0xD0) ||                       /* call reg */
           (b[4] == 0xFF && (b[5] & 0xF8) == 0x10) ||                       /* call [reg] */
           (b[3] == 0xFF && (b[4] & 0xF8) == 0x50) ||                       /* call [reg+d8] */
           (b[0] == 0xFF && (b[1] == 0x15 || (b[1] & 0xF8) == 0x90)) ||     /* call [abs] / [reg+d32] */
           b[1] == 0xE8;                                                    /* call rel32 */
    return call && memcmp(b + 6, follow, sizeof follow) == 0;
}

/* atomically repoint the vptr of an object (SEH-guarded) */
static int SwapVptr(DWORD obj, DWORD newVt)
{
    __try { InterlockedExchange((volatile LONG *)obj, (LONG)newVt); } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 1;
}

/* manager: copy the vtable once (after read-only verification), then (re)publish the vptr */
static void MgrMaintain(void)
{
    DWORD vp = 0, own = (DWORD)(UINT_PTR)&g_mgrVt[1];
    static DWORD lastOther;
    if (g_mgrFailed || !RdU32(A_MGR, &vp)) return;
    if (vp == own) return;
    if (vp != VT_MGR) {
        if (g_mgrEver && vp != lastOther) { Log("manager vptr changed to 0x%08lX (not ours, not original); waiting", vp); lastOther = vp; }
        return;
    }
    if (!g_mgrBuilt) {
        static const BYTE getter[7] = { 0x8B,0x81,0x9C,0x09,0x00,0x00,0xC3 };
        DWORD s10 = 0;
        BYTE g[7];
        int i, n = 0;
        if (!Rd(VT_MGR - 4, g_mgrVt, sizeof g_mgrVt) || !RdU32(VT_MGR + MGR_SLOT * 4, &s10) || !Rd(0x641DB0, g, 7)) {
            Log("manager hook: vtable/getter unreadable - skipped"); g_mgrFailed = 1; return;
        }
        if (s10 != 0x00641DB0 || memcmp(g, getter, 7) != 0) {
            char hx[40]; HexStr(g, 7, hx);
            Log("manager hook: slot %d = 0x%08lX, getter bytes %s unexpected - skipped", MGR_SLOT, s10, hx);
            g_mgrFailed = 1; return;
        }
        for (i = 0; i < NWL; i++) {
            BYTE got[18]; char hx[60];
            g_wl[i].on = WlSiteOk(g_wl[i].ra, got);
            HexStr(got + 6, 12, hx);
            Log("  camera site 0x%X: %s (follow bytes %s)%s", g_wl[i].ra, g_wl[i].on ? "verified" : "MISMATCH - dropped", hx,
                i == NWL - 1 ? (g_gyroAim ? " [aim-assist site, not whitelisted: GyroAimAssist=1]" : " [aim-assist site whitelisted: aim assist OFF on mouse frames]") : "");
            n += g_wl[i].on;
        }
        g_mgrVt[1 + MGR_SLOT] = (DWORD)(UINT_PTR)HookGetActiveDevice;
        MemoryBarrier();
        g_mgrBuilt = 1;
        Log("manager hook: vtable copy at %p built (slot %d: 0x00641DB0 -> %p), %d of %d whitelist sites active", &g_mgrVt[1], MGR_SLOT, HookGetActiveDevice, n, NWL);
    }
    if (!SwapVptr(A_MGR, own)) { Log("manager hook: vptr write failed"); g_mgrFailed = 1; return; }
    Log("%s: manager 0x%X vptr 0x%08lX -> %p", g_mgrEver ? "manager hook RE-INSTALLED" : "manager hook installed", A_MGR, VT_MGR, &g_mgrVt[1]);
    g_mgrEver = 1;
    InterlockedExchange(&g_mgrOk, 1);
}

static int IsOurDevVt(DWORD vp)
{
    int k;
    for (k = 0; k < g_ndvt; k++) if (vp == (DWORD)(UINT_PTR)&g_dvt[k].buf[1]) return 1;
    return 0;
}

static DEVVT *DevVtFor(DWORD orig)
{
    static const BYTE getter[4] = { 0x8B,0x41,0x78,0xC3 };
    DEVVT *e;
    DWORD s1 = 0;
    BYTE g[4];
    char hx[16];
    int k;
    for (k = 0; k < g_ndvt; k++) if (g_dvt[k].orig == orig) return &g_dvt[k];
    if (g_ndvt >= 4) return NULL;
    e = &g_dvt[g_ndvt];
    memset(g, 0, sizeof g);
    e->orig = orig;
    if (!Rd(orig - 4, e->buf, sizeof e->buf) || !RdU32(orig + DEV_SLOT * 4, &s1) || !Rd(s1, g, 4)) {
        Log("device vtable 0x%08lX: unreadable - skipped", orig);
        e->ok = 0; g_ndvt++; return e;
    }
    HexStr(g, 4, hx);
    if (memcmp(g, getter, 4) != 0) {
        Log("device vtable 0x%08lX: GetType slot -> 0x%08lX bytes %s unexpected (want 8B 41 78 C3) - skipped", orig, s1, hx);
        e->ok = 0;
    } else {
        Log("device vtable 0x%08lX: GetType slot -> 0x%08lX bytes %s ok; copy at %p", orig, s1, hx, &e->buf[1]);
        e->buf[1 + DEV_SLOT] = (DWORD)(UINT_PTR)HookGetType;
        MemoryBarrier();
        e->ok = 1;
    }
    g_ndvt++;
    return e;
}

/* switch fix: mouse (and keyboard with PadLock=1) report type 4 to the active-device switch only */
static void SwapDevices(void)
{
    static const BYTE ctx[] = { 0x8B,0x0E,0x8B,0x01,0x8B,0x50,0x04,0xFF,0xD2,0x83,0xF8,0x04,0x0F,0x84,0xB7,0x00,0x00,0x00,
                                0x8B,0x0E,0x8B,0x01,0x8B,0x50,0x08,0x33,0xFF,0xFF,0xD2 };
    DWORD n = 0, i;
    if (g_swCtx < 0 || !RdU32(A_DEVCOUNT, &n) || !n) return;
    if (n > 32) n = 32;
    for (i = 0; i < n; i++) {
        DWORD dev = 0, ty = 0xFF, vp = 0;
        DEVVT *e;
        if (!RdU32(A_DEVLIST + i * 4, &dev) || !dev || !RdU32(dev + 0x78, &ty)) continue;
        if (!(ty == 0 || (g_padLock && ty == 1))) continue;
        if (!RdU32(dev, &vp) || !vp) continue;
        if (IsOurDevVt(vp)) { if (ty == 0) InterlockedExchange(&g_mouseSwapped, 1); continue; }
        if (g_swCtx == 0) {
            BYTE cur[sizeof ctx];
            if (!Rd(0x7F7F08, cur, sizeof cur)) { Log("switch fix: 0x7F7F08 unreadable - skipped"); g_swCtx = -1; return; }
            if (memcmp(cur, ctx, sizeof ctx) != 0) {
                char hx[100]; HexStr(cur, sizeof cur, hx);
                Log("switch fix: unexpected bytes at 0x7F7F08: %s - skipped", hx); g_swCtx = -1; return;
            }
            g_swCtx = 1;
            Log("switch fix: context at 0x7F7F08 verified");
        }
        e = DevVtFor(vp);
        if (!e || !e->ok) continue;
        if (!SwapVptr(dev, (DWORD)(UINT_PTR)&e->buf[1])) { Log("switch fix: vptr write failed for device 0x%08lX", dev); continue; }
        Log("switch fix: device 0x%08lX type=%lu vptr 0x%08lX -> %p", dev, ty, vp, &e->buf[1]);
        if (ty == 0) InterlockedExchange(&g_mouseSwapped, 1);
    }
}

static volatile LONG g_maintBusy;
static void Maintain(void)
{
    if (GetModuleHandleA(NULL) != (HMODULE)0x400000) return;
    if (InterlockedExchange(&g_maintBusy, 1)) return;
    if (g_doP2) MgrMaintain();
    if (g_doP1) SwapDevices();
    InterlockedExchange(&g_maintBusy, 0);
}

static void MaintainTick(void)            /* from the XInput wrapper, about once per second */
{
    static DWORD last;
    DWORD now = GetTickCount();
    if (now - last < 1000) return;
    last = now;
    Maintain();
}

/* ---- IAT patch: exe XInputGetState slot -> MixedGetState ---- */
static int PatchIat(void)
{
    BYTE *exe = (BYTE *)GetModuleHandleA(NULL);
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *dir;
    IMAGE_IMPORT_DESCRIPTOR *d;
    void *exp = (void *)GetProcAddress(g_self, "XInputGetState");
    if (!exe || !exp) return 0;
    p_PadState = (PFN_GetState)exp;
    nt = (IMAGE_NT_HEADERS *)(exe + ((IMAGE_DOS_HEADER *)exe)->e_lfanew);
    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->VirtualAddress) return 0;
    for (d = (IMAGE_IMPORT_DESCRIPTOR *)(exe + dir->VirtualAddress); d->Name; d++) {
        IMAGE_THUNK_DATA *t, *oft;
        if (_stricmp((char *)(exe + d->Name), "xinput9_1_0.dll") != 0) continue;
        oft = d->OriginalFirstThunk ? (IMAGE_THUNK_DATA *)(exe + d->OriginalFirstThunk) : NULL;
        for (t = (IMAGE_THUNK_DATA *)(exe + d->FirstThunk); t->u1.Function; t++, oft = oft ? oft + 1 : NULL) {
            int match = (void *)t->u1.Function == exp;
            if (!match && oft && !(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
                match = strcmp((char *)((IMAGE_IMPORT_BY_NAME *)(exe + oft->u1.AddressOfData))->Name, "XInputGetState") == 0;
            if (match) {
                DWORD old;
                if (!VirtualProtect(&t->u1.Function, 4, PAGE_READWRITE, &old)) return 0;
                Log("IAT slot %p (RVA 0x%X): %p -> MixedGetState", &t->u1.Function, (unsigned)((BYTE *)t - exe), (void *)t->u1.Function);
                t->u1.Function = (DWORD_PTR)MixedGetState;
                VirtualProtect(&t->u1.Function, 4, old, &old);
                return 1;
            }
        }
    }
    return 0;
}

/* ---- DirectInput hook: own throw-away mouse device, patch the shared vtable[9] ---- */
static int InstallDIHook(void)
{
    typedef HRESULT (WINAPI *PFN_Create)(HINSTANCE, DWORD, REFIID, LPVOID *, LPUNKNOWN);
    HMODULE h = GetModuleHandleA("dinput8.dll");
    PFN_Create create;
    IDirectInput8A *di = NULL;
    IDirectInputDevice8A *dev = NULL;
    void **vt;
    HRESULT hr;
    DWORD old;
    if (g_diHooked) return 1;
    if (!h) {
        char sys[MAX_PATH];
        GetSystemDirectoryA(sys, MAX_PATH);
        strcat(sys, "\\dinput8.dll");
        h = LoadLibraryA(sys);
        if (!h) return 0;
    }
    create = (PFN_Create)GetProcAddress(h, "DirectInput8Create");
    if (!create) return 0;
    hr = create(GetModuleHandleA(NULL), DIRECTINPUT_VERSION, &IID_IDirectInput8A, (LPVOID *)&di, NULL);
    if (FAILED(hr) || !di) { Log("DirectInput8Create failed hr=0x%08lX", (unsigned long)hr); return 0; }
    hr = di->lpVtbl->CreateDevice(di, &GUID_SysMouse, &dev, NULL);
    if (FAILED(hr) || !dev) {
        Log("CreateDevice(SysMouse) failed hr=0x%08lX", (unsigned long)hr);
        di->lpVtbl->Release(di);
        return 0;
    }
    vt = *(void ***)dev;
    if (vt[9] != (void *)Hook_GetDeviceState && VirtualProtect(&vt[9], sizeof(void *), PAGE_READWRITE, &old)) {
        o_GDS = (PFN_GDS)vt[9];
        vt[9] = (void *)Hook_GetDeviceState;
        VirtualProtect(&vt[9], sizeof(void *), old, &old);
        InterlockedExchange(&g_diHooked, 1);
        Log("dinput8 device vtable %p hooked (dinput8 at %p): GetDeviceState %p -> hook", vt, h, o_GDS);
    } else {
        Log("dinput8 vtable patch failed (vtable %p)", vt);
    }
    dev->lpVtbl->Release(dev);
    di->lpVtbl->Release(di);
    return g_diHooked != 0;
}

static DWORD WINAPI InstallThread(LPVOID unused)
{
    int i, diTries = 0;
    BYTE *exe = (BYTE *)GetModuleHandleA(NULL);
    (void)unused;
    Log("exe base %p%s", exe, exe == (BYTE *)0x400000 ? "" : " (NOT 0x400000: vptr hooks will be skipped)");
    Log("parts: PatchSwitch=%d PatchCamera=%d HookMouse=%d HookXInput=%d CrashLog=%d", g_doP1, g_doP2, g_doDI, g_doIat, g_crashLog);
    if (!g_doIat) Log("IAT patch disabled (HookXInput=0)");
    else if (PatchIat()) InterlockedExchange(&g_iatOk, 1);
    else Log("IAT patch failed: wrapper runs from the export itself");
    if (!g_doDI) Log("DirectInput hook disabled (HookMouse=0)");
    if (!g_doP1) Log("switch fix disabled (PatchSwitch=0)");
    if (!g_doP2) Log("camera hook disabled (PatchCamera=0)");
    /* poll every 50 ms (up to ~120 s) until the game has constructed the manager and the devices exist;
       the XInput wrapper keeps maintaining afterwards */
    for (i = 0; i < 2400; i++) {
        int mgrDone = !g_doP2 || exe != (BYTE *)0x400000 || g_mgrOk || g_mgrFailed;
        int devDone = !g_doP1 || exe != (BYTE *)0x400000 || g_mouseSwapped || g_swCtx < 0;
        if (g_doDI && !g_diHooked && diTries < 300 && (i % 2) == 0) { diTries++; InstallDIHook(); }
        if (mgrDone && devDone && (!g_doDI || g_diHooked || diTries >= 300)) break;
        if (exe == (BYTE *)0x400000) Maintain();
        Sleep(50);
    }
    if (g_doP2 && !g_mgrOk && !g_mgrFailed) Log("manager hook not installed within the poll window; the XInput wrapper keeps trying");
    if (g_doP1 && !g_mouseSwapped && g_swCtx >= 0) Log("mouse device not swapped within the poll window; the XInput wrapper keeps trying");
    if (g_doDI && !g_diHooked) Log("DirectInput GetDeviceState hook FAILED after retries; mouse stays native");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        char sys[MAX_PATH], sum[400];
        DisableThreadLibraryCalls(inst);
        g_self = inst;
        GetSystemDirectoryA(sys, MAX_PATH);          /* SysWOW64 for a 32-bit process */
        strcat(sys, "\\xinput9_1_0.dll");
        g_real = LoadLibraryA(sys);
        if (g_real) {
            p_GetState = (PFN_GetState)GetProcAddress(g_real, "XInputGetState");
            p_SetState = (PFN_SetState)GetProcAddress(g_real, "XInputSetState");
            p_GetCaps  = (PFN_GetCaps)GetProcAddress(g_real, "XInputGetCapabilities");
            p_Guids    = (PFN_Guids)GetProcAddress(g_real, "XInputGetDSoundAudioDeviceGuids");
        }
        LoadSettings(inst);
        if (g_ini[0]) {
            strcpy(g_log, g_ini);
            strcpy(strrchr(g_log, '.'), ".log");
            DeleteFileA(g_log);
        }
        SettingsSummary(sum, sizeof sum);
        Log("xinput_mouse (Hitman Absolution dual input) loaded: %s", sum);
        Log("real dll: %s -> %s", sys, g_real ? "loaded" : "FAILED to load");
        if (g_crashLog) AddVectoredExceptionHandler(1, CrashVeh);
        CloseHandle(CreateThread(NULL, 0, InstallThread, NULL, 0, NULL));
    }
    return TRUE;
}
