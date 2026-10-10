using System;
using WandEnhancer.Models;

namespace WandEnhancer.Core.Patching.Strategies
{
    internal interface IPatchStrategy
    {
        bool RequiresLauncherAlways { get; }

        void ApplyEnablement(PatchContext context);

        bool Launch(PatchContext context, string args);
    }

    internal sealed class PatchContext
    {
        public PatchContext(WeModConfig install, Action<string, ELogType> log, string unpackedPath = null,
            bool replacesLauncher = false)
        {
            Install = install;
            Log = log;
            UnpackedPath = unpackedPath;
            ReplacesLauncher = replacesLauncher;
        }

        public WeModConfig Install { get; }
        public Action<string, ELogType> Log { get; }

        /// <summary>Root of extracted app.asar.unpacked tree (null at launch)</summary>
        public string UnpackedPath { get; }

        public bool ReplacesLauncher { get; }
    }
}
