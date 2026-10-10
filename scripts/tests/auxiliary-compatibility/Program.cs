using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using WandEnhancer.Core.Patching.Strategies.Static;

internal static class Program
{
    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static string BuildFixture(string project, string scratch, string variant)
    {
        string output = Path.Combine(scratch, variant);
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string arg in new[] { "build", project, "--nologo", "--verbosity", "quiet", "--configuration", "Release",
            "--output", output, "-p:FixtureVariant=" + variant }) start.ArgumentList.Add(arg);
        using (var process = Process.Start(start))
        {
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            process.WaitForExit();
            if (process.ExitCode != 0) throw new Exception(stdout.Result + stderr.Result);
        }
        return Path.Combine(output, "AuxiliaryFixture.dll");
    }

    private static HashSet<int> CheckPatchedBodies(string before, string after, bool replacesLauncher, int expectedContent)
    {
        byte[] original = File.ReadAllBytes(before), patched = File.ReadAllBytes(after);
        Assert(original.Length == patched.Length, "Patching changed PE length.");
        var offsets = new List<long>();
        using (var image = DotNetImage.Load(before))
        {
            offsets.AddRange(image.FindPInvokeCallerBodyOffsets("WinVerifyTrust"));
            var content = image.FindClientContentCheckBodyOffsets(replacesLauncher);
            Assert(content.Count == expectedContent, "Unexpected content check count.");
            offsets.AddRange(content);
        }
        var allowedBytes = new HashSet<long>(offsets.SelectMany(offset => new[] { offset, offset + 1, offset + 2 }));
        for (int i = 0; i < original.Length; i++)
            Assert(original[i] == patched[i] || allowedBytes.Contains(i), "Unrelated byte changed at " + i);

        using (var pe = new PEReader(new MemoryStream(patched)))
        {
            var reader = pe.GetMetadataReader();
            var modifiedTokens = new HashSet<int>();
            foreach (var handle in reader.MethodDefinitions)
            {
                var method = reader.GetMethodDefinition(handle);
                if (method.RelativeVirtualAddress == 0) continue;
                int rva = method.RelativeVirtualAddress;
                var section = pe.PEHeaders.SectionHeaders[pe.PEHeaders.GetContainingSectionIndex(rva)];
                long offset = section.PointerToRawData + rva - section.VirtualAddress;
                if (!offsets.Contains(offset)) continue;
                var body = pe.GetMethodBody(rva);
                Assert(body.GetILBytes().SequenceEqual(new byte[] { 0x16, 0x2A }), "Invalid patched IL.");
                Assert(body.ExceptionRegions.Length == 0 && body.LocalSignature.IsNil, "Old EH/locals retained.");
                modifiedTokens.Add(MetadataTokens.GetToken(handle));
            }
            Assert(modifiedTokens.Count == offsets.Distinct().Count(), "A planned body was not patched.");
            return modifiedTokens;
        }
    }

    private static string PatchFixture(string source, string scratch, string name, bool trust, bool launcher, int expectedContent)
    {
        string copy = Path.Combine(scratch, name + ".dll");
        File.Copy(source, copy);
        int patched = AuxTrustNeutralizer.Neutralize(copy, null, trust, launcher);
        Assert(patched == expectedContent + 1, "Unexpected patch count for " + name);
        CheckPatchedBodies(source, copy, launcher, expectedContent);
        return copy;
    }

    private static void CheckRejected(string source, string scratch, string name)
    {
        string copy = Path.Combine(scratch, name + ".dll");
        File.Copy(source, copy);
        byte[] before = File.ReadAllBytes(copy);
        bool rejected = false;
        try { AuxTrustNeutralizer.Neutralize(copy, null); }
        catch (InvalidOperationException) { rejected = true; }
        Assert(rejected, "Unsupported fixture accepted: " + name);
        Assert(before.SequenceEqual(File.ReadAllBytes(copy)), "Unsupported fixture partially modified: " + name);
    }

    public static void Main(string[] args)
    {
        string fixtureProject = args[0];
        string scratch = Path.Combine(Path.GetTempPath(), "wand-aux-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(scratch);
        try
        {
            string modern = BuildFixture(fixtureProject, scratch, "MODERN");
            string legacy = BuildFixture(fixtureProject, scratch, "LEGACY");
            PatchFixture(modern, scratch, "static", true, false, 2);
            PatchFixture(modern, scratch, "static-auto-update", true, true, 3);
            string supervised = PatchFixture(modern, scratch, "supervised", false, true, 3);
            PatchFixture(legacy, scratch, "legacy-static", true, false, 0);
            string legacyCopy = Path.Combine(scratch, "legacy-supervised.dll");
            File.Copy(legacy, legacyCopy);
            Assert(AuxTrustNeutralizer.Neutralize(legacyCopy, null, false, true) == 0, "Legacy supervised should not patch.");
            Assert(File.ReadAllBytes(legacy).SequenceEqual(File.ReadAllBytes(legacyCopy)), "Legacy supervised signature changed.");

            string renamed = Path.Combine(scratch, "renamed-enum.dll");
            byte[] obfuscated = File.ReadAllBytes(modern);
            byte[] storageName = System.Text.Encoding.UTF8.GetBytes("value__\0");
            int nameOffset = obfuscated.AsSpan().IndexOf(storageName);
            Assert(nameOffset >= 0, "Fixture enum storage field missing.");
            Array.Clear(obfuscated, nameOffset, storageName.Length);
            obfuscated[nameOffset] = (byte)'0';
            File.WriteAllBytes(renamed, obfuscated);
            PatchFixture(renamed, scratch, "obfuscated-storage", true, false, 2);

            foreach (string variant in new[] { "PARTIAL", "AMBIGUOUS", "WRONG_SIGNATURE" })
                CheckRejected(BuildFixture(fixtureProject, scratch, variant), scratch, variant);

            // Actually JIT the synthetic patched methods, including former try/finally bodies.
            var context = new System.Runtime.Loader.AssemblyLoadContext("wand-fixture", isCollectible: true);
            // Loading from bytes avoids locking the temporary fixture DLL on Windows.
            Type fixture;
            using (var input = new MemoryStream(File.ReadAllBytes(supervised)))
                fixture = context.LoadFromStream(input).GetType("AuxiliaryFixture");
            Assert((uint)fixture.GetMethod("NativeTrust").Invoke(null, null) == 0, "Patched trust body did not JIT.");
            var caller = fixture.GetMethod("CheckCaller");
            Assert((bool)caller.Invoke(null, new object[] { "Wand.exe", true, "enhancer" }), "Patched client rejected.");
            Assert(!(bool)caller.Invoke(null, new object[] { "Other.exe", true, "enhancer" }), "Caller-name check lost.");
            Assert(!(bool)caller.Invoke(null, new object[] { "Wand.exe", false, "enhancer" }), "Publisher check lost.");
            context.Unload();

            // Real proprietary binaries are optional inputs, never committed or executed.
            if (args.Length > 1)
            {
                string original = args[1];
                var tokens = CheckRealCopy(original, scratch, "real-static", true, false, 2);
                Console.WriteLine("Real static method tokens: " + string.Join(", ", tokens.Select(t => t.ToString("X8"))));
                tokens = CheckRealCopy(original, scratch, "real-supervised", false, true, 3);
                Console.WriteLine("Real supervised method tokens: " + string.Join(", ", tokens.Select(t => t.ToString("X8"))));
            }
            Console.WriteLine("Auxiliary compatibility tests passed: Static, auto-update, Supervised, legacy, rejection, valid IL, preserved caller checks.");
        }
        finally { Directory.Delete(scratch, true); }
    }

    private static HashSet<int> CheckRealCopy(string source, string scratch, string name, bool trust, bool launcher, int count)
    {
        string copy = PatchFixture(source, scratch, name, trust, launcher, count);
        return CheckPatchedBodies(source, copy, launcher, count);
    }
}
