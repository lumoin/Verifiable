using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// A cryptographic suite specification is responsible for specifying the verification method type and its associated verification material.For example, see JSON Web Signature 2020 and Ed25519 Signature 2020.
    /// For all registered verification method types and associated verification material available for DIDs, please see the <see href="https://www.w3.org/TR/did-spec-registries">>DID Specification Registries</<see>.
    /// <see href="https://www.w3.org/TR/did-core/#verification-methods">Verification methods</see>.
    /// </summary>
    [DebuggerDisplay("VerificationMethod(Id = {Id}, Type = {Type}, KeyFormat = {KeyFormat})")]
    public class VerificationMethod
    {
        //TODO: Could be FractionOrUri: Uri, or C# 10/F# discriminated union (like VerificationRelationship would be).
        public string? Id { get; set; }

        public string? Type { get; set; }

        public string? Controller { get; set; }

        public KeyFormat? KeyFormat { get; set; }
    }
}
