/* trigger.c -- deliberately trips the mitigations Witness watches for.
 *
 * Build (Developer PowerShell, /GS is on by default):   cl /W4 /GS trigger.c
 * Run one at a time and confirm Witness produces a bundle, a toast and a report.
 *
 *   trigger fastfail   __fastfail() -> Application Error 1000, exception 0xC0000409
 *   trigger gs         /GS cookie smash -> same event, via the security-cookie check
 *   trigger rwx        VirtualProtect to RWX. Prints whether ACG allowed it. To make
 *                      it fire: Windows Security > App & browser control > Exploit
 *                      protection settings > Program settings > add trigger.exe >
 *                      Arbitrary code guard: On. Then re-run; expect Security-
 *                      Mitigations/KernelMode event 2 and a Witness "look" report.
 *   trigger child      CreateProcess("cmd.exe /c exit"). With "Do not allow child
 *                      processes" on for trigger.exe, expect KernelMode event 4.
 *   trigger lowil <path-to-low-integrity-copy.exe>
 *                      LoadLibraryW of a file labelled Low integrity (README shows
 *                      the icacls command). With "Block low integrity images" on,
 *                      expect KernelMode event 6.
 *   trigger remote \\server\share\some.dll
 *                      LoadLibraryW from a UNC path. With "Block remote images" on
 *                      for trigger.exe, expect Security-Mitigations/KernelMode
 *                      event 8 and a Witness "urgent" report. See README.md for
 *                      how to make a loopback share without leaving it lying around.
 *
 * Nothing here is an exploit. Each case is the textbook "the protection worked"
 * outcome, which is exactly what Witness is supposed to notice.
 */
#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>

static volatile size_t overrun = 64; /* volatile so the compiler cannot prove the overflow away */

static int smash_cookie(void) {
    char buf[8];
    memset(buf, 'A', overrun); /* /GS cookie is corrupted; detected at return */
    return buf[0];
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "fastfail") == 0) {
        __fastfail(FAST_FAIL_INCORRECT_STACK); /* never returns */
    }
    if (argc > 1 && strcmp(argv[1], "gs") == 0) {
        return smash_cookie(); /* never returns normally */
    }
    if (argc > 1 && strcmp(argv[1], "rwx") == 0) {
        DWORD old = 0;
        void *p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (p == NULL) { puts("VirtualAlloc failed"); return 3; }
        if (!VirtualProtect(p, 4096, PAGE_EXECUTE_READWRITE, &old)) {
            printf("VirtualProtect refused (error %lu): ACG is on, Witness should have fired\n", GetLastError());
            return 2;
        }
        puts("RWX granted: ACG is NOT enabled for trigger.exe; enable it and re-run");
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        STARTUPINFOW si = { sizeof si };
        PROCESS_INFORMATION pi;
        wchar_t cmd[] = L"cmd.exe /c exit";
        if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            printf("CreateProcess refused (error %lu): child-process block is on, Witness should have fired\n", GetLastError());
            return 2;
        }
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        puts("child process ran: DisallowChildProcessCreation is NOT enabled for trigger.exe");
        return 0;
    }
    if (argc > 2 && (strcmp(argv[1], "remote") == 0 || strcmp(argv[1], "lowil") == 0)) {
        wchar_t path[1024];
        if (MultiByteToWideChar(CP_ACP, 0, argv[2], -1, path, 1024) == 0) { puts("bad path"); return 3; }
        HMODULE h = LoadLibraryW(path);
        if (h == NULL) {
            DWORD e = GetLastError();
            /* ERROR_ACCESS_DENIED (5) or ERROR_DYNAMIC_CODE_BLOCKED-style refusals mean the mitigation fired. */
            printf("LoadLibraryW refused (error %lu): if the matching image-load block is on, Witness should have fired\n", e);
            return 2;
        }
        FreeLibrary(h);
        puts("image loaded: the matching image-load block is NOT enabled for trigger.exe; enable it and re-run");
        return 0;
    }
    puts("usage: trigger fastfail | gs | rwx | child | remote <unc-path> | lowil <low-integrity-path>");
    return 1;
}
