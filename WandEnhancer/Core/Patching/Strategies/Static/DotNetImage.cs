using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace WandEnhancer.Core.Patching.Strategies.Static
{
    internal sealed class DotNetImage : IDisposable
    {
        private readonly byte[] _bytes;
        private readonly PEReader _pe;
        private readonly MetadataReader _reader;

        private DotNetImage(byte[] bytes, PEReader pe, MetadataReader reader)
        {
            _bytes = bytes;
            _pe = pe;
            _reader = reader;
        }

        public static DotNetImage Load(string path)
        {
            byte[] bytes = File.ReadAllBytes(path);
            var pe = new PEReader(ImmutableArray.Create(bytes));
            try
            {
                if (!pe.HasMetadata)
                {
                    pe.Dispose();
                    return null;
                }

                return new DotNetImage(bytes, pe, pe.GetMetadataReader());
            }
            catch (BadImageFormatException)
            {
                pe.Dispose();
                return null;
            }
        }

        public void Dispose() => _pe.Dispose();

        /// File offset of the body header of every method that calls the P/Invoke.
        public IReadOnlyList<long> FindPInvokeCallerBodyOffsets(string importName)
        {
            var hits = new List<long>();
            int token = FindMethodToken(importName);
            if (token == 0)
            {
                return hits;
            }

            foreach (MethodDefinitionHandle handle in _reader.MethodDefinitions)
            {
                int rva = _reader.GetMethodDefinition(handle).RelativeVirtualAddress;
                if (rva == 0)
                {
                    continue; // Abstract, P/Invoke, or otherwise bodyless.
                }

                try
                {
                    if (BodyCalls(_pe.GetMethodBody(rva).GetILBytes(), token))
                    {
                        if (!ReturnsStatus(handle))
                            throw new InvalidOperationException("Unsupported auxiliary trust-check return type.");
                        hits.Add(BodyFileOffset(rva));
                    }
                }
                catch (BadImageFormatException)
                {
                    // Malformed body: skip rather than trust a wrong offset.
                }
            }

            return hits;
        }

        /// <summary>
        /// Finds the independent disk/memory fuse and ASAR-header checks in newer auxiliaries.
        /// The surrounding publisher, executable-name and RPC caller checks remain intact.
        /// </summary>
        public IReadOnlyList<long> FindClientContentCheckBodyOffsets(bool replacesLauncher = false)
        {
            bool hasClientIntegrity = FindMethodsWithStrings("Client integrity check failed.").Count != 0;
            var asarChecks = FindMethodsWithStrings("resources\\app.asar", "SHA256");
            var fuseReaders = FindMethodsWithStrings(
                "The Electron fuse sentinel was not found.", "The Electron fuse wire is invalid.");
            if (!hasClientIntegrity && asarChecks.Count == 0 && fuseReaders.Count == 0)
                return new long[0]; // Older auxiliaries only have the Authenticode check.
            if (!hasClientIntegrity)
                throw new InvalidOperationException("Unsupported auxiliary client integrity capability.");
            if (asarChecks.Count != 1 || fuseReaders.Count != 1)
                throw new InvalidOperationException("Unsupported auxiliary client integrity checks: ASAR/fuse anchors are not unique.");

            var asarCheck = asarChecks[0];
            int readerToken = MetadataTokens.GetToken(fuseReaders[0]);
            var fuseChecks = new List<MethodDefinitionHandle>();
            foreach (var handle in _reader.MethodDefinitions)
            {
                var method = _reader.GetMethodDefinition(handle);
                if (method.RelativeVirtualAddress != 0 && ReturnsStatus(handle) &&
                    BodyCalls(_pe.GetMethodBody(method.RelativeVirtualAddress).GetILBytes(), readerToken))
                    fuseChecks.Add(handle);
            }

            if (fuseChecks.Count != 1 || !ReturnsStatus(asarCheck) ||
                StatusReturnType(asarCheck) != StatusReturnType(fuseChecks[0]))
                throw new InvalidOperationException("Unsupported auxiliary client integrity check signatures.");

            var offsets = new List<long>
            {
                BodyFileOffset(_reader.GetMethodDefinition(fuseChecks[0]).RelativeVirtualAddress),
                BodyFileOffset(_reader.GetMethodDefinition(asarCheck).RelativeVirtualAddress)
            };
            if (replacesLauncher)
            {
                var launcherChecks = FindMethodsWithStrings("app-", "Wand.exe");
                launcherChecks.RemoveAll(handle => StatusReturnType(handle) != StatusReturnType(asarCheck));
                if (launcherChecks.Count != 1)
                    throw new InvalidOperationException("Unsupported auxiliary launcher integrity check.");
                offsets.Add(BodyFileOffset(_reader.GetMethodDefinition(launcherChecks[0]).RelativeVirtualAddress));
            }
            return offsets;
        }

        private List<MethodDefinitionHandle> FindMethodsWithStrings(params string[] anchors)
        {
            var hits = new List<MethodDefinitionHandle>();
            foreach (var handle in _reader.MethodDefinitions)
            {
                int rva = _reader.GetMethodDefinition(handle).RelativeVirtualAddress;
                if (rva == 0) continue;
                byte[] il = _pe.GetMethodBody(rva).GetILBytes();
                var found = new HashSet<string>();
                for (int ip = 0; ip < il.Length; ip = NextInstruction(il, ip))
                {
                    if (il[ip] != 0x72 || ip + 5 > il.Length) continue; // ldstr
                    int token = (int)ReadU32(il, ip + 1);
                    if ((token & unchecked((int)0xFF000000)) != 0x70000000)
                        throw new BadImageFormatException("Invalid auxiliary string token.");
                    found.Add(_reader.GetUserString(MetadataTokens.UserStringHandle(token & 0x00FFFFFF)));
                }
                if (Array.TrueForAll(anchors, found.Contains)) hits.Add(handle);
            }
            return hits;
        }

        private int StatusReturnType(MethodDefinitionHandle handle)
        {
            var method = _reader.GetMethodDefinition(handle);
            if ((method.Attributes & System.Reflection.MethodAttributes.Static) == 0) return -1;
            var signature = _reader.GetBlobReader(method.Signature);
            byte header = signature.ReadByte();
            if ((header & 0x10) != 0) return -1; // Generic methods are not supported.
            signature.ReadCompressedInteger(); // Parameter count.
            int type = signature.ReadByte();
            if (type == 0x08 || type == 0x09) return type; // Int32 / UInt32.
            if (type != 0x11) return -1; // A value type must be an Int32 enum with a zero member.
            int encoded = signature.ReadCompressedInteger();
            if ((encoded & 3) != 0) return -1; // Local TypeDef only.
            var definition = _reader.GetTypeDefinition(MetadataTokens.TypeDefinitionHandle(encoded >> 2));
            if (definition.BaseType.Kind != HandleKind.TypeReference ||
                _reader.GetString(_reader.GetTypeReference((TypeReferenceHandle)definition.BaseType).Name) != "Enum")
                return -1;
            bool int32Storage = false, zeroMember = false;
            int storageFields = 0;
            foreach (var fieldHandle in definition.GetFields())
            {
                var field = _reader.GetFieldDefinition(fieldHandle);
                // Wand obfuscates even the enum storage field's name; use its shape.
                if ((field.Attributes & System.Reflection.FieldAttributes.Static) == 0)
                {
                    storageFields++;
                    var fieldSignature = _reader.GetBlobReader(field.Signature);
                    int32Storage = fieldSignature.ReadByte() == 0x06 && fieldSignature.ReadByte() == 0x08;
                }
                var constantHandle = field.GetDefaultValue();
                if (!constantHandle.IsNil)
                {
                    var constant = _reader.GetConstant(constantHandle);
                    if (constant.TypeCode == ConstantTypeCode.Int32 &&
                        _reader.GetBlobReader(constant.Value).ReadInt32() == 0) zeroMember = true;
                }
            }
            return storageFields == 1 && int32Storage && zeroMember ? 0x1000000 | encoded : -1;
        }

        private bool ReturnsStatus(MethodDefinitionHandle handle) => StatusReturnType(handle) != -1;

        private int FindMethodToken(string name)
        {
            foreach (MethodDefinitionHandle handle in _reader.MethodDefinitions)
            {
                if (_reader.GetString(_reader.GetMethodDefinition(handle).Name) == name)
                {
                    return MetadataTokens.GetToken(handle);
                }
            }

            return 0;
        }

        private long BodyFileOffset(int rva)
        {
            SectionHeader section = _pe.PEHeaders.SectionHeaders[_pe.PEHeaders.GetContainingSectionIndex(rva)];
            int headerOffset = section.PointerToRawData + (rva - section.VirtualAddress);
            if (headerOffset < 0 || headerOffset > _bytes.Length - 3 || _pe.GetMethodBody(rva).GetILBytes().Length < 2)
                throw new BadImageFormatException("Auxiliary method is too short for a status body.");
            return headerOffset;
        }

        private static int NextInstruction(byte[] il, int ip)
        {
            int next;
            if (il[ip] == 0xFE)
            {
                if (ip + 2 > il.Length) throw new BadImageFormatException("Truncated auxiliary IL opcode.");
                next = ip + 2 + TwoByte[il[ip + 1]];
            }
            else if (il[ip] == 0x45)
            {
                if (ip + 5 > il.Length) throw new BadImageFormatException("Truncated auxiliary IL switch.");
                long end = ip + 5L + 4L * ReadU32(il, ip + 1);
                if (end > il.Length) throw new BadImageFormatException("Invalid auxiliary IL switch.");
                next = (int)end;
            }
            else next = ip + 1 + OneByte[il[ip]];
            if (next > il.Length) throw new BadImageFormatException("Truncated auxiliary IL operand.");
            return next;
        }

        // Walks instruction boundaries so the token can't match operand data of another instruction.
        private static bool BodyCalls(byte[] il, int token)
        {
            int ip = 0;
            while (ip < il.Length)
            {
                byte op = il[ip];
                if ((op == 0x28 || op == 0x6F) && ip + 5 <= il.Length && (int)ReadU32(il, ip + 1) == token)
                {
                    return true;
                }
                ip = NextInstruction(il, ip);
            }

            return false;
        }

        private static uint ReadU32(byte[] b, int i) =>
            (uint)(b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24));

        #region IL operand sizes

        private static readonly int[] OneByte = BuildOneByteOperands();
        private static readonly int[] TwoByte = BuildTwoByteOperands();

        private static int[] BuildOneByteOperands()
        {
            var s = new int[256];
            foreach (int op in new[] { 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F })
            {
                s[op] = 1;
            }

            s[0x20] = 4; s[0x21] = 8; s[0x22] = 4; s[0x23] = 8;
            for (int op = 0x2B; op <= 0x37; op++) s[op] = 1; // short branches
            for (int op = 0x38; op <= 0x44; op++) s[op] = 4; // long branches
            s[0xDD] = 4; s[0xDE] = 1; // leave, leave.s
            foreach (int op in new[]
                     {
                         0x27, 0x28, 0x29, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79, 0x7B, 0x7C,
                         0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0
                     })
            {
                s[op] = 4; // metadata token operands
            }

            return s;
        }

        private static int[] BuildTwoByteOperands()
        {
            var s = new int[256];
            foreach (int op in new[] { 0x06, 0x07, 0x15, 0x16, 0x1C }) s[op] = 4; // ldftn..sizeof: tokens
            foreach (int op in new[] { 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E }) s[op] = 2; // ldarg..stloc: u2
            s[0x12] = 1; s[0x19] = 1; // unaligned., no.: prefixes with a 1-byte operand
            return s;
        }

        #endregion
    }
}
