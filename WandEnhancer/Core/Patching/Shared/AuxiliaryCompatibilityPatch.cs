using System;
using System.IO;
using System.Linq;
using WandEnhancer.Core.Patching.Strategies;
using WandEnhancer.Core.Patching.Strategies.Static;

namespace WandEnhancer.Core.Patching.Shared
{
    internal static class AuxiliaryCompatibilityPatch
    {
        public static void Apply(PatchContext context, bool requireTrustPatch)
        {
            if (string.IsNullOrEmpty(context.UnpackedPath))
                throw new InvalidOperationException("[ENHANCER] Extracted auxiliary path is unavailable.");

            string directory = Path.Combine(context.UnpackedPath, "static", "unpacked", "auxiliary");
            var auxiliaries = Directory.Exists(directory)
                ? Directory.EnumerateFiles(directory, "*AuxiliaryService.exe").ToArray()
                : new string[0];
            if (auxiliaries.Length == 0)
            {
                context.Log?.Invoke("[ENHANCER] No auxiliary service found; skipping compatibility patch.", ELogType.Info);
                return;
            }
            if (auxiliaries.Length != 1)
                throw new InvalidOperationException("[ENHANCER] Auxiliary service is ambiguous; refusing to patch.");

            if (AuxTrustNeutralizer.Neutralize(auxiliaries[0], context.Log, requireTrustPatch,
                replacesLauncher: !requireTrustPatch || context.ReplacesLauncher) < 0)
                throw new InvalidOperationException("[ENHANCER] Could not adapt auxiliary checks; the service would reject the patched client.");
        }
    }
}
