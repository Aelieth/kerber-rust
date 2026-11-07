# WS's Windows side, one mode per run, started by rp-ws.sh through the guest agent. Each secret comes
# in a file the host wrote, deleted on read; none is printed or put on a command line.
# No parameter attribute: that would make an advanced script, which refuses the modes' positional arguments.
param([string]$Mode)
$ErrorActionPreference = "Stop"
$T = "C:\Windows\Temp"

function Take([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { Write-Output "SECRET_MISSING"; exit 2 }
    $lines = @(Get-Content -LiteralPath $Path)
    Remove-Item -LiteralPath $Path -Force
    return ,$lines
}

# klist tgt prints the session key's bytes and the encoded ticket: neither leaves the guest.
function Show([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { Write-Output "FILE_MISSING"; return }
    $skip = $false
    foreach ($l in Get-Content -LiteralPath $Path) {
        if ($l.StartsWith("==")) { $skip = $false }
        if ($skip -or $l -match "KeyLength") { continue }
        Write-Output $l
        if ($l -match "^EncodedTicket") { $skip = $true }
    }
}

Add-Type -IgnoreWarnings -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

public static class WsNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle { public IntPtr Lo; public IntPtr Hi; }
    [StructLayout(LayoutKind.Sequential)]
    public struct SecBuffer { public int cbBuffer; public int BufferType; public IntPtr pvBuffer; }
    [StructLayout(LayoutKind.Sequential)]
    public struct SecBufferDesc { public int ulVersion; public int cBuffers; public IntPtr pBuffers; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct AuthId {
        public string User; public int UserLength;
        public string Domain; public int DomainLength;
        public string Password; public int PasswordLength;
        public int Flags;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct Sizes { public int cbMaxToken; public int cbMaxSignature; public int cbBlockSize; public int cbSecurityTrailer; }
    [StructLayout(LayoutKind.Sequential)]
    public struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    public struct ChangePassword {
        public int MessageType;
        public UnicodeString DomainName; public UnicodeString AccountName;
        public UnicodeString OldPassword; public UnicodeString NewPassword;
        public byte Impersonating;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectAttributes {
        public int Length; public IntPtr RootDirectory; public IntPtr ObjectName;
        public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct StartupInfo {
        public int cb; public string reserved; public string desktop; public string title;
        public int x; public int y; public int xsize; public int ysize;
        public int xchars; public int ychars; public int fill; public int flags;
        public short show; public short reserved2;
        public IntPtr reserved3; public IntPtr stdin; public IntPtr stdout; public IntPtr stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInformation { public IntPtr process; public IntPtr thread; public int pid; public int tid; }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    static extern int AcquireCredentialsHandle(string principal, string package, int use, IntPtr logonId,
        IntPtr authData, IntPtr getKey, IntPtr getKeyArg, ref SecHandle cred, out long expiry);
    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    static extern int InitializeSecurityContext(ref SecHandle cred, IntPtr ctxIn, string target, int req,
        int reserved1, int drep, IntPtr input, int reserved2, ref SecHandle ctx, ref SecBufferDesc output,
        out int attr, out long expiry);
    [DllImport("secur32.dll")]
    static extern int QueryContextAttributes(ref SecHandle ctx, int attr, ref Sizes sizes);
    [DllImport("secur32.dll")]
    static extern int MakeSignature(ref SecHandle ctx, int qop, ref SecBufferDesc msg, int seq);
    [DllImport("secur32.dll")]
    static extern int VerifySignature(ref SecHandle ctx, ref SecBufferDesc msg, int seq, out int qop);
    [DllImport("secur32.dll")]
    static extern int EncryptMessage(ref SecHandle ctx, int qop, ref SecBufferDesc msg, int seq);
    [DllImport("secur32.dll")]
    static extern int DecryptMessage(ref SecHandle ctx, ref SecBufferDesc msg, int seq, out int qop);
    [DllImport("secur32.dll")]
    static extern int DeleteSecurityContext(ref SecHandle ctx);
    [DllImport("secur32.dll")]
    static extern int FreeCredentialsHandle(ref SecHandle cred);
    [DllImport("secur32.dll")]
    static extern int LsaConnectUntrusted(out IntPtr lsa);
    [DllImport("secur32.dll")]
    static extern int LsaLookupAuthenticationPackage(IntPtr lsa, ref UnicodeString name, out int package);
    [DllImport("secur32.dll")]
    static extern int LsaCallAuthenticationPackage(IntPtr lsa, int package, IntPtr submit, int submitLength,
        out IntPtr ret, out int retLength, out int protocolStatus);
    [DllImport("secur32.dll")]
    static extern int LsaFreeReturnBuffer(IntPtr buffer);
    [DllImport("secur32.dll")]
    static extern int LsaDeregisterLogonProcess(IntPtr lsa);
    [DllImport("advapi32.dll")]
    static extern int LsaOpenPolicy(IntPtr system, ref ObjectAttributes attrs, int access, out IntPtr policy);
    [DllImport("advapi32.dll")]
    static extern int LsaStorePrivateData(IntPtr policy, ref UnicodeString key, ref UnicodeString data);
    [DllImport("advapi32.dll")]
    static extern int LsaClose(IntPtr policy);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithLogonW(string user, string domain, string password, int logonFlags,
        string app, string cmd, int creationFlags, IntPtr env, string dir, ref StartupInfo si,
        out ProcessInformation pi);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUser(string user, string domain, string password, int logonType, int provider,
        out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int infoClass, out TokenStatistics info, int length,
        out int returned);

    [StructLayout(LayoutKind.Sequential)]
    public struct Luid { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    public struct TokenStatistics {
        public Luid TokenId; public Luid AuthenticationId; public long ExpirationTime;
        public int TokenType; public int ImpersonationLevel; public int DynamicCharged; public int DynamicAvailable;
        public int GroupCount; public int PrivilegeCount; public Luid ModifiedId;
    }

    const int ISC_REQ = 0x0001001E;
    const int SEC_I_CONTINUE_NEEDED = 0x00090312;
    const int SECBUFFER_DATA = 1, SECBUFFER_TOKEN = 2, SECBUFFER_PADDING = 9, SECBUFFER_STREAM = 10;
    // KERB_PROTOCOL_MESSAGE_TYPE's eighth member (learn.microsoft.com: ne-ntsecapi-kerb_protocol_message_type).
    const int KerbChangePasswordMessage = 7;

    static List<string> said;
    static void Say(string line) { said.Add(line); }
    static string Hex(int v) { return "0x" + v.ToString("X8"); }

    static IntPtr Copy(byte[] b) {
        IntPtr p = Marshal.AllocHGlobal(Math.Max(b.Length, 1));
        Marshal.Copy(b, 0, p, b.Length);
        return p;
    }
    static byte[] Take(SecBuffer b) {
        byte[] r = new byte[Math.Max(b.cbBuffer, 0)];
        if (b.cbBuffer > 0) Marshal.Copy(b.pvBuffer, r, 0, b.cbBuffer);
        return r;
    }
    static SecBuffer Buf(int cb, int type, IntPtr p) {
        SecBuffer b = new SecBuffer();
        b.cbBuffer = cb; b.BufferType = type; b.pvBuffer = p;
        return b;
    }
    static int BufSize { get { return Marshal.SizeOf(typeof(SecBuffer)); } }
    static IntPtr Array(params SecBuffer[] bufs) {
        IntPtr a = Marshal.AllocHGlobal(bufs.Length * BufSize);
        for (int i = 0; i < bufs.Length; i++) Marshal.StructureToPtr(bufs[i], IntPtr.Add(a, i * BufSize), false);
        return a;
    }
    static SecBuffer Get(IntPtr a, int i) {
        return (SecBuffer)Marshal.PtrToStructure(IntPtr.Add(a, i * BufSize), typeof(SecBuffer));
    }
    static SecBufferDesc Desc(int n, IntPtr a) {
        SecBufferDesc d = new SecBufferDesc();
        d.ulVersion = 0; d.cBuffers = n; d.pBuffers = a;
        return d;
    }
    // RFC 4121 4.2.6: the token ID, the flags octet and, for a wrap token, RRC at octets 6-7.
    static string Tok(byte[] t) {
        if (t.Length < 16) return "tok=short";
        string s = "tok=" + t[0].ToString("x2") + t[1].ToString("x2") + " flags=" + t[2].ToString("x2");
        if (t[0] == 5 && t[1] == 4) s += " rrc=" + ((t[6] << 8) | t[7]);
        return s;
    }

    static void Send(NetworkStream s, byte[] b) {
        byte[] n = BitConverter.GetBytes(b.Length);
        if (BitConverter.IsLittleEndian) System.Array.Reverse(n);
        s.Write(n, 0, 4);
        s.Write(b, 0, b.Length);
        s.Flush();
    }
    static byte[] ReadN(NetworkStream s, int n) {
        byte[] b = new byte[n];
        int got = 0;
        while (got < n) {
            int r = s.Read(b, got, n - got);
            if (r <= 0) throw new Exception("short read");
            got += r;
        }
        return b;
    }
    static byte[] Recv(NetworkStream s) {
        byte[] h = ReadN(s, 4);
        if (BitConverter.IsLittleEndian) System.Array.Reverse(h);
        int n = BitConverter.ToInt32(h, 0);
        if (n <= 0 || n > 1048576) throw new Exception("bad token length " + n);
        return ReadN(s, n);
    }

    static int Acquire(string user, string realm, string pw, ref SecHandle cred) {
        AuthId id = new AuthId();
        id.User = user; id.UserLength = user.Length;
        id.Domain = realm; id.DomainLength = realm.Length;
        id.Password = pw; id.PasswordLength = pw.Length;
        id.Flags = 2;
        IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(AuthId)));
        Marshal.StructureToPtr(id, p, false);
        long exp;
        int rc = AcquireCredentialsHandle(null, "Kerberos", 2, IntPtr.Zero, p, IntPtr.Zero, IntPtr.Zero, ref cred, out exp);
        Marshal.DestroyStructure(p, typeof(AuthId));
        Marshal.FreeHGlobal(p);
        return rc;
    }

    static int Isc(ref SecHandle cred, ref SecHandle ctx, bool have, string target, byte[] input, out byte[] output, out int attr) {
        IntPtr outMem = Marshal.AllocHGlobal(65536);
        IntPtr outArr = Array(Buf(65536, SECBUFFER_TOKEN, outMem));
        SecBufferDesc outDesc = Desc(1, outArr);
        IntPtr inMem = IntPtr.Zero, inArr = IntPtr.Zero, inDesc = IntPtr.Zero, ctxIn = IntPtr.Zero;
        if (input != null) {
            inMem = Copy(input);
            inArr = Array(Buf(input.Length, SECBUFFER_TOKEN, inMem));
            inDesc = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBufferDesc)));
            Marshal.StructureToPtr(Desc(1, inArr), inDesc, false);
        }
        if (have) {
            ctxIn = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecHandle)));
            Marshal.StructureToPtr(ctx, ctxIn, false);
        }
        long exp;
        int rc = InitializeSecurityContext(ref cred, ctxIn, target, ISC_REQ, 0, 0x10, inDesc, 0, ref ctx, ref outDesc, out attr, out exp);
        output = Take(Get(outArr, 0));
        foreach (IntPtr p in new IntPtr[] { outMem, outArr, inMem, inArr, inDesc, ctxIn }) {
            if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
        }
        return rc;
    }

    static int Sign(ref SecHandle ctx, byte[] msg, int max, out byte[] sig) {
        IntPtr d = Copy(msg), t = Marshal.AllocHGlobal(max);
        IntPtr a = Array(Buf(msg.Length, SECBUFFER_DATA, d), Buf(max, SECBUFFER_TOKEN, t));
        SecBufferDesc desc = Desc(2, a);
        int rc = MakeSignature(ref ctx, 0, ref desc, 0);
        sig = Take(Get(a, 1));
        Marshal.FreeHGlobal(d); Marshal.FreeHGlobal(t); Marshal.FreeHGlobal(a);
        return rc;
    }

    static int Verify(ref SecHandle ctx, byte[] msg, byte[] sig, out int qop) {
        IntPtr d = Copy(msg), t = Copy(sig);
        IntPtr a = Array(Buf(msg.Length, SECBUFFER_DATA, d), Buf(sig.Length, SECBUFFER_TOKEN, t));
        SecBufferDesc desc = Desc(2, a);
        int rc = VerifySignature(ref ctx, ref desc, 0, out qop);
        Marshal.FreeHGlobal(d); Marshal.FreeHGlobal(t); Marshal.FreeHGlobal(a);
        return rc;
    }

    static int Seal(ref SecHandle ctx, byte[] msg, Sizes z, out byte[] wire) {
        int tokN = Math.Max(z.cbSecurityTrailer, 64), padN = Math.Max(z.cbBlockSize, 64);
        IntPtr t = Marshal.AllocHGlobal(tokN), d = Copy(msg), p = Marshal.AllocHGlobal(padN);
        IntPtr a = Array(Buf(tokN, SECBUFFER_TOKEN, t), Buf(msg.Length, SECBUFFER_DATA, d), Buf(padN, SECBUFFER_PADDING, p));
        SecBufferDesc desc = Desc(3, a);
        int rc = EncryptMessage(ref ctx, 0, ref desc, 0);
        List<byte> w = new List<byte>();
        for (int i = 0; i < 3; i++) w.AddRange(Take(Get(a, i)));
        wire = w.ToArray();
        Marshal.FreeHGlobal(t); Marshal.FreeHGlobal(d); Marshal.FreeHGlobal(p); Marshal.FreeHGlobal(a);
        return rc;
    }

    static int Unseal(ref SecHandle ctx, byte[] tok, out byte[] plain, out int qop) {
        IntPtr st = Copy(tok);
        IntPtr a = Array(Buf(tok.Length, SECBUFFER_STREAM, st), Buf(0, SECBUFFER_DATA, IntPtr.Zero));
        SecBufferDesc desc = Desc(2, a);
        int rc = DecryptMessage(ref ctx, ref desc, 0, out qop);
        plain = rc == 0 ? Take(Get(a, 1)) : new byte[0];
        Marshal.FreeHGlobal(st); Marshal.FreeHGlobal(a);
        return rc;
    }

    // S1 and S2 against an acceptor started with both switches: the context, a MIC, a wrap, then the
    // acceptor's wrapped reply and its MIC.
    public static List<string> Context(string peer, int port, string target, string user, string realm, string pw) {
        said = new List<string>();
        SecHandle cred = new SecHandle(), ctx = new SecHandle();
        int rc = Acquire(user, realm, pw, ref cred);
        Say("ACQUIRE_RC:" + Hex(rc));
        if (rc != 0) return said;
        bool have = false;
        TcpClient tcp = new TcpClient();
        try {
            tcp.Connect(peer, port);
            NetworkStream s = tcp.GetStream();
            s.ReadTimeout = 30000;
            byte[] input = null;
            int attr = 0;
            bool done = false;
            for (int i = 0; i < 6 && !done; i++) {
                byte[] output;
                rc = Isc(ref cred, ref ctx, have, target, input, out output, out attr);
                have = true;
                Say("ISC_RC:" + i + ":" + Hex(rc));
                Say("ISC_OUT:" + i + ":" + output.Length);
                if (output.Length > 0) Send(s, output);
                if (rc == 0) done = true;
                else if (rc == SEC_I_CONTINUE_NEEDED) { input = Recv(s); Say("ISC_IN:" + i + ":" + input.Length); }
                else { Say("ISC_STOP:" + Hex(rc)); return said; }
            }
            if (!done) { Say("ISC_STOP:rounds"); return said; }
            Say("ISC_ATTR:" + Hex(attr));
            Sizes z = new Sizes();
            rc = QueryContextAttributes(ref ctx, 0, ref z);
            Say("SIZES_RC:" + Hex(rc) + " sig=" + z.cbMaxSignature + " block=" + z.cbBlockSize + " trailer=" + z.cbSecurityTrailer);
            byte[] msg = Encoding.ASCII.GetBytes("hello-mic-from-win-sspi"), sig;
            rc = Sign(ref ctx, msg, z.cbMaxSignature, out sig);
            Say("MAKESIG_RC:" + Hex(rc) + " " + Tok(sig));
            if (rc != 0) return said;
            Send(s, msg);
            Send(s, sig);
            byte[] wire;
            rc = Seal(ref ctx, Encoding.ASCII.GetBytes("hello-from-win-sspi"), z, out wire);
            Say("ENCRYPT_RC:" + Hex(rc) + " " + Tok(wire));
            if (rc != 0) return said;
            Send(s, wire);
            byte[] back = Recv(s), plain;
            int qop;
            rc = Unseal(ref ctx, back, out plain, out qop);
            Say("DECRYPT_RC:" + Hex(rc) + " qop=" + qop + " " + Tok(back));
            if (rc != 0) return said;
            Say("REPLY_TEXT:" + Encoding.ASCII.GetString(plain));
            byte[] rmic = Recv(s);
            rc = Verify(ref ctx, plain, rmic, out qop);
            Say("VERIFY_RC:" + Hex(rc) + " qop=" + qop + " " + Tok(rmic));
            Say("SSPI_DONE");
        } catch (Exception e) {
            Say("SSPI_ERROR:" + e.Message);
        } finally {
            tcp.Close();
            if (have) DeleteSecurityContext(ref ctx);
            FreeCredentialsHandle(ref cred);
        }
        return said;
    }

    // One InitializeSecurityContext call with no peer: its AS and TGS exchanges, or the error they end in.
    public static List<string> Ticket(string target, string user, string realm, string pw) {
        said = new List<string>();
        SecHandle cred = new SecHandle(), ctx = new SecHandle();
        int rc = Acquire(user, realm, pw, ref cred);
        Say("ACQUIRE_RC:" + Hex(rc));
        if (rc != 0) return said;
        byte[] output;
        int attr;
        rc = Isc(ref cred, ref ctx, false, target, null, out output, out attr);
        Say("ISC_RC:0:" + Hex(rc));
        Say("ISC_OUT:0:" + (output.Length > 0 ? "token" : "none"));
        if (rc == 0 || rc == SEC_I_CONTINUE_NEEDED) DeleteSecurityContext(ref ctx);
        FreeCredentialsHandle(ref cred);
        return said;
    }

    static UnicodeString Us(string v) {
        UnicodeString u = new UnicodeString();
        u.Buffer = Marshal.StringToHGlobalUni(v);
        u.Length = (ushort)(v.Length * 2);
        u.MaximumLength = (ushort)(v.Length * 2 + 2);
        return u;
    }

    public static List<string> ChangePasswordMsg(string user, string realm, string oldPw, string newPw) {
        said = new List<string>();
        IntPtr lsa;
        int st = LsaConnectUntrusted(out lsa);
        Say("LSA_CONNECT:" + Hex(st));
        if (st != 0) return said;
        byte[] kb = Encoding.ASCII.GetBytes("Kerberos");
        UnicodeString name = new UnicodeString();
        name.Buffer = Copy(kb);
        name.Length = (ushort)kb.Length;
        name.MaximumLength = (ushort)kb.Length;
        int pkg;
        st = LsaLookupAuthenticationPackage(lsa, ref name, out pkg);
        Say("LSA_PACKAGE:" + Hex(st));
        if (st == 0) {
            string[] parts = new string[] { realm, user, oldPw, newPw };
            int head = Marshal.SizeOf(typeof(ChangePassword)), total = head;
            foreach (string p in parts) total += p.Length * 2;
            IntPtr blk = Marshal.AllocHGlobal(total);
            UnicodeString[] us = new UnicodeString[4];
            int off = head;
            for (int i = 0; i < 4; i++) {
                byte[] b = Encoding.Unicode.GetBytes(parts[i]);
                Marshal.Copy(b, 0, IntPtr.Add(blk, off), b.Length);
                us[i].Buffer = IntPtr.Add(blk, off);
                us[i].Length = (ushort)b.Length;
                us[i].MaximumLength = (ushort)b.Length;
                off += b.Length;
            }
            ChangePassword req = new ChangePassword();
            req.MessageType = KerbChangePasswordMessage;
            req.DomainName = us[0]; req.AccountName = us[1]; req.OldPassword = us[2]; req.NewPassword = us[3];
            req.Impersonating = 0;
            Marshal.StructureToPtr(req, blk, false);
            IntPtr ret;
            int retLen, proto;
            st = LsaCallAuthenticationPackage(lsa, pkg, blk, total, out ret, out retLen, out proto);
            Say("CHPW_LSA:" + Hex(st));
            Say("CHPW_PROTOCOL:" + Hex(proto));
            if (ret != IntPtr.Zero) LsaFreeReturnBuffer(ret);
            Marshal.Copy(new byte[total], 0, blk, total);
            Marshal.FreeHGlobal(blk);
        }
        Marshal.FreeHGlobal(name.Buffer);
        LsaDeregisterLogonProcess(lsa);
        return said;
    }

    // The machine password ksetup /setcomputerpassword stores: the local secret `$MACHINE.ACC (nf-ntsecapi-lsastoreprivatedata).
    public static List<string> MachinePassword(string pw) {
        said = new List<string>();
        ObjectAttributes oa = new ObjectAttributes();
        oa.Length = Marshal.SizeOf(typeof(ObjectAttributes));
        IntPtr pol;
        int st = LsaOpenPolicy(IntPtr.Zero, ref oa, 0x000F0FFF, out pol);
        Say("LSA_OPEN:" + Hex(st));
        if (st != 0) return said;
        UnicodeString key = Us("`$MACHINE.ACC"), data = Us(pw);
        st = LsaStorePrivateData(pol, ref key, ref data);
        Say("LSA_STORE:" + Hex(st));
        Marshal.FreeHGlobal(key.Buffer);
        Marshal.FreeHGlobal(data.Buffer);
        LsaClose(pol);
        return said;
    }

    // LOGON_NETCREDENTIALS_ONLY (2): the caller's token, these credentials on the network (nf-winbase-createprocesswithlogonw).
    public static List<string> Launch(string user, string domain, string pw, string cmd, int waitMs) {
        said = new List<string>();
        StartupInfo si = new StartupInfo();
        si.cb = Marshal.SizeOf(typeof(StartupInfo));
        ProcessInformation pi;
        bool ok = CreateProcessWithLogonW(user, domain, pw, 2, null, cmd, 0, IntPtr.Zero, null, ref si, out pi);
        Say("CREATE:" + ok + " LAST:" + Marshal.GetLastWin32Error());
        if (ok) {
            uint wait = WaitForSingleObject(pi.process, (uint)waitMs), code;
            GetExitCodeProcess(pi.process, out code);
            CloseHandle(pi.process);
            CloseHandle(pi.thread);
            Say("WAIT:" + wait + " EXIT:" + code);
        }
        return said;
    }

    // L1: the realm logon itself (LOGON32_LOGON_INTERACTIVE 2, LOGON32_PROVIDER_DEFAULT 0; nf-winbase-logonuserw),
    // then that session's tickets by its LUID (TokenStatistics 10, nf-securitybaseapi-gettokeninformation;
    // ns-winnt-token_statistics; klist -li), read while the token keeps the session alive.
    public static List<string> Logon(string user, string domain, string pw) {
        said = new List<string>();
        IntPtr tok;
        bool ok = LogonUser(user, domain, pw, 2, 0, out tok);
        Say("LOGON:" + ok + " LAST:" + (ok ? 0 : Marshal.GetLastWin32Error()));
        if (!ok) return said;
        try {
            TokenStatistics st;
            int got;
            if (!GetTokenInformation(tok, 10, out st, Marshal.SizeOf(typeof(TokenStatistics)), out got)) {
                Say("LOGON_LUID:none LAST:" + Marshal.GetLastWin32Error());
                return said;
            }
            string args = "-li 0x" + st.AuthenticationId.LowPart.ToString("x");
            if (st.AuthenticationId.HighPart != 0) args += " -lh 0x" + st.AuthenticationId.HighPart.ToString("x");
            System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("klist.exe", args);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (System.Diagnostics.Process klist = System.Diagnostics.Process.Start(psi)) {
                string text = klist.StandardOutput.ReadToEnd() + klist.StandardError.ReadToEnd();
                klist.WaitForExit();
                Say("==KLIST_SESSION");
                foreach (string line in text.Split('\n')) Say(line.TrimEnd('\r'));
            }
        } finally {
            CloseHandle(tok);
        }
        return said;
    }

    public static List<string> Http(string url) {
        said = new List<string>();
        HttpWebRequest r = (HttpWebRequest)WebRequest.Create(url);
        r.AllowAutoRedirect = false;
        r.UseDefaultCredentials = true;
        r.Timeout = 30000;
        HttpWebResponse resp = null;
        try {
            resp = (HttpWebResponse)r.GetResponse();
        } catch (WebException e) {
            resp = e.Response as HttpWebResponse;
            if (resp == null) Say("HTTP_ERROR:" + e.Status);
        }
        if (resp != null) {
            Say("HTTP_STATUS:" + (int)resp.StatusCode);
            string loc = resp.Headers["Location"];
            if (loc != null) {
                int q = loc.IndexOf('?');
                Say("HTTP_LOCATION:" + (q < 0 ? loc : loc.Substring(0, q)));
                Say("HTTP_CODE:" + (loc.Contains("&code=") || loc.Contains("?code=") ? "yes" : "no"));
            }
            resp.Close();
        }
        return said;
    }
}
"@

$ps = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
switch ($Mode) {
    "info" {
        $p = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Write-Output ("WIN_HOST:" + $p.Hostname)
        Write-Output ("WIN_SUFFIX:" + $p.'NV Domain')
        Write-Output ("WIN_BUILD:" + [Environment]::OSVersion.Version)
        Write-Output ("WIN_UTC:" + [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"))
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } |
            ForEach-Object { Write-Output ("WIN_IPV4:" + $_.IPAddress) }
    }
    "suffix" {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Set-ItemProperty -Path $key -Name "NV Domain" -Value $args[0]
        Write-Output ("WIN_SUFFIX_SET:" + (Get-ItemProperty $key).'NV Domain')
    }
    "ca" {
        $c = Import-Certificate -FilePath $args[0] -CertStoreLocation Cert:\LocalMachine\Root
        Write-Output ("CA_IMPORTED:" + $c.Subject)
        Remove-Item -LiteralPath $args[0] -Force
    }
    "machinepw" {
        $pw = (Take $args[0])[0]
        [WsNative]::MachinePassword($pw)
    }
    "reach" {
        try {
            $a = Resolve-DnsName -Name $args[0] -Type A | Where-Object { $_.Type -eq "A" }
            Write-Output ("DNS_A:" + ($a.IPAddress -join ","))
        } catch { Write-Output ("DNS_A:error " + $_.Exception.Message) }
        $c = New-Object System.Net.Sockets.TcpClient
        try { $open = $c.ConnectAsync($args[0], 88).Wait(5000) -and $c.Connected } catch { $open = $false }
        $c.Close()
        Write-Output ("TCP88:" + $(if ($open) { "open" } else { "closed" }))
    }
    "klist" {
        $user, $realm, $spn, $pwFile = $args
        $pw = (Take $pwFile)[0]
        $out = "$T\ws-klist.txt"
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        # The redirection goes first: "echo ... 0>>file" would read the 0 as a handle number.
        $cmd = "@echo off`r`n" +
            ">$out echo ==KLIST`r`nklist >>$out 2>&1`r`n" +
            ">>$out echo ==KLIST_TGT_BEFORE`r`nklist tgt >>$out 2>&1`r`n" +
            ">>$out echo ==KLIST_GET`r`nklist get $spn >>$out 2>&1`r`n" +
            ">>$out echo ==KLIST_GET_RC %ERRORLEVEL%`r`n" +
            ">>$out echo ==KLIST_TGT`r`nklist tgt >>$out 2>&1`r`n" +
            ">>$out echo ==KLIST_DONE`r`n"
        [IO.File]::WriteAllText("$T\ws-run.cmd", $cmd)
        [WsNative]::Launch($user, $realm, $pw, "`"C:\Windows\System32\cmd.exe`" /c $T\ws-run.cmd", 120000)
        $pw = $null
        Show $out
    }
    "sspi" {
        $peer, $port, $target, $user, $realm, $pwFile = $args
        $pw = (Take $pwFile)[0]
        [WsNative]::Context($peer, [int]$port, $target, $user, $realm, $pw)
    }
    "ticket" {
        $target, $user, $realm, $pwFile = $args
        $pw = (Take $pwFile)[0]
        [WsNative]::Ticket($target, $user, $realm, $pw)
    }
    "chpw" {
        $user, $realm, $pwFile = $args
        $pw = Take $pwFile
        [WsNative]::ChangePasswordMsg($user, $realm, $pw[0], $pw[1])
    }
    "k1" {
        $url, $user, $realm, $pwFile = $args
        $pw = (Take $pwFile)[0]
        $out = "$T\ws-k1.txt"
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        [IO.File]::WriteAllText("$T\ws-k1.url", $url)
        [WsNative]::Launch($user, $realm, $pw, "`"$ps`" -NoProfile -ExecutionPolicy Bypass -File $T\ws.ps1 k1-inner", 120000)
        $pw = $null
        Show $out
    }
    "k1-inner" {
        $out = "$T\ws-k1.txt"
        $lines = [WsNative]::Http([IO.File]::ReadAllText("$T\ws-k1.url"))
        $lines += "==KLIST"
        $lines += (& klist.exe 2>&1 | ForEach-Object { "$_" })
        [IO.File]::WriteAllLines($out, [string[]]$lines)
    }
    "logon" {
        $user, $realm, $pwFile = $args
        $pw = (Take $pwFile)[0]
        [WsNative]::Logon($user, $realm, $pw)
        $pw = $null
    }
    "etype" {
        # R1c: the client's Kerberos encryption types (Learn: "Network security: Configure encryption types
        # allowed for Kerberos"); 4 is RC4-HMAC-MD5 only, "none" removes the value.
        $key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
        if (-not (Test-Path $key)) { New-Item -Path $key | Out-Null }
        if ($args[0] -eq "none") {
            Remove-ItemProperty -Path $key -Name SupportedEncryptionTypes -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $key -Name SupportedEncryptionTypes -Value ([int]$args[0]) -Type DWord
        }
        $v = (Get-ItemProperty -Path $key).SupportedEncryptionTypes
        Write-Output ("ETYPE_POLICY:" + $(if ($null -eq $v) { "none" } else { $v }))
    }
    default { Write-Output "MODE_UNKNOWN:$Mode"; exit 2 }
}
Write-Output "PS_DONE"
