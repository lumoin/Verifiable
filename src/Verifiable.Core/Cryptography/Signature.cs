using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Represents a signature.
    /// </summary>
    public class Signature: SensitiveMemory
    {
        /// <summary>
        /// A Signature constructor.
        /// </summary>
        /// <param name="sensitiveMemory">The byte array that represents a signature.</param>
        public Signature(IMemoryOwner<byte> sensitiveMemory): base(sensitiveMemory) { }

        /// <summary>
        /// An implicit conversion from <see cref="Signature"/> to <see cref="ReadOnlySpan{byte}"/>.
        /// </summary>
        /// <param name="signature"></param>
        [DebuggerStepThrough, MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static implicit operator ReadOnlySpan<byte>(Signature signature) => signature.AsReadOnlySpan();
    }
}
