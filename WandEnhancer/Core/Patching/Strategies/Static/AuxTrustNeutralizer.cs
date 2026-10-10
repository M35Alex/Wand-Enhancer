using System;
using System.Collections.Generic;
using System.IO;

namespace WandEnhancer.Core.Patching.Strategies.Static
{
    /// <summary>
    /// Adapts auxiliary trust and Electron content checks to the patched local client.
    /// </summary>
    internal static class AuxTrustNeutralizer
    {
        private const string ImportName = "WinVerifyTrust";
        // Tiny method header (2 IL bytes), then ldc.i4.0; ret. Replacing the header
        // also removes old locals/EH sections; inserting ret into a try region is invalid IL.
        private static readonly byte[] Stub = { 0x0A, 0x16, 0x2A };

        /// <returns>Methods stubbed, or -1 on failure.</returns>
        public static int Neutralize(string auxPath, Action<string, ELogType> log,
            bool requireTrustPatch = true, bool replacesLauncher = false)
        {
            var offsets = new HashSet<long>();
            int contentChecks;
            using (DotNetImage image = DotNetImage.Load(auxPath))
            {
                if (image == null)
                {
                    log?.Invoke($"[ENHANCER] {Path.GetFileName(auxPath)} is not a managed image; leaving it alone.", ELogType.Warn);
                    return -1;
                }

                var contentOffsets = image.FindClientContentCheckBodyOffsets(replacesLauncher);
                contentChecks = contentOffsets.Count;
                // Supervised keeps signed Wand.exe on disk. Legacy auxiliaries need no edits.
                if (!requireTrustPatch && contentChecks == 0)
                {
                    log?.Invoke("[ENHANCER] Auxiliary has no separate client content checks; no compatibility patch needed.", ELogType.Info);
                    return 0;
                }
                var trustOffsets = image.FindPInvokeCallerBodyOffsets(ImportName);
                if (trustOffsets.Count == 0)
                {
                    log?.Invoke($"[ENHANCER] No {ImportName} caller found in {Path.GetFileName(auxPath)}; the aux may have changed.", ELogType.Warn);
                    return -1;
                }
                foreach (long offset in trustOffsets) offsets.Add(offset);
                foreach (long offset in contentOffsets) offsets.Add(offset);
            }

            int stubbed = 0;
            using (var stream = new FileStream(auxPath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            {
                foreach (long offset in offsets)
                {
                    stream.Position = offset;
                    bool already = stream.ReadByte() == Stub[0] && stream.ReadByte() == Stub[1] && stream.ReadByte() == Stub[2];
                    if (already)
                    {
                        continue;
                    }

                    stream.Position = offset;
                    stream.Write(Stub, 0, Stub.Length);
                    stubbed++;
                }
            }

            log?.Invoke($"[ENHANCER] Auxiliary compatibility applied ({stubbed} method(s), {contentChecks} content/launcher checks).", ELogType.Info);
            return stubbed;
        }
    }
}
