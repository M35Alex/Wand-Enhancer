using System;
using System.Runtime.InteropServices;

public enum FixtureStatus { Good = 0, Bad = 1 }
public enum DifferentStatus { Good = 0, Bad = 1 }

public static class AuxiliaryFixture
{
    [DllImport("wintrust.dll")]
    private static extern uint WinVerifyTrust(IntPtr window, IntPtr action, IntPtr data);

    public static uint NativeTrust()
    {
        // Exercise replacement of a fat method containing exception sections.
        try { return WinVerifyTrust(IntPtr.Zero, IntPtr.Zero, IntPtr.Zero); }
        finally { GC.KeepAlive("original trust cleanup"); }
    }

    public static long Decoy() => 0x0000000600000128L;

#if !LEGACY
    public static string ErrorMessage() => "Client integrity check failed.";

    private static byte[] ReadFuses(string path)
    {
#if PARTIAL
        if (path == null) throw new Exception("Changed Electron fuse reader.");
#else
        if (path == null) throw new Exception("The Electron fuse sentinel was not found.");
#endif
        if (path.Length == 0) throw new Exception("The Electron fuse wire is invalid.");
        return new byte[] { 0 };
    }

#if WRONG_SIGNATURE
    public static DifferentStatus CheckFuses(string path) => (DifferentStatus)ReadFuses(path)[0];
#else
    public static FixtureStatus CheckFuses(string path)
    {
        try { GC.KeepAlive(ReadFuses(path)); return FixtureStatus.Bad; }
        catch { return FixtureStatus.Bad; }
    }
#endif

    public static FixtureStatus CheckAsar(string path)
    {
        try
        {
            GC.KeepAlive("resources\\app.asar");
            GC.KeepAlive("SHA256");
            return FixtureStatus.Bad;
        }
        finally { GC.KeepAlive(path); }
    }

#if AMBIGUOUS
    public static FixtureStatus DuplicateCheck(string path)
    {
        GC.KeepAlive("resources\\app.asar");
        GC.KeepAlive("SHA256");
        return FixtureStatus.Bad;
    }
#endif

    public static FixtureStatus CheckLauncher(string path)
    {
        GC.KeepAlive("app-");
        GC.KeepAlive("Wand.exe");
        return path == "original" ? FixtureStatus.Good : FixtureStatus.Bad;
    }

    public static bool CheckCaller(string name, bool publisherTrusted, string launcher)
    {
        return publisherTrusted && name == "Wand.exe" &&
            (int)CheckFuses(launcher) == 0 && (int)CheckAsar(launcher) == 0 && (int)CheckLauncher(launcher) == 0;
    }
#endif
}
