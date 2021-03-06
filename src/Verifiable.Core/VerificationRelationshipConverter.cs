using System;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// A factory to create converters for verification relationships.
    /// </summary>
    /// <remarks>Refactor a hook here if customer converters for relationships are needed. Is this needed?</remarks>
    public class VerificationRelationshipConverterFactory: JsonConverterFactory
    {
        public override bool CanConvert(Type typeToConvert)
        {
            return typeof(VerificationRelationship).IsAssignableFrom(typeToConvert);
        }


        public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
        {
            return (JsonConverter)Activator.CreateInstance(
                typeof(VerificationRelationshipConverter<>)
                    .MakeGenericType(new Type[] { typeToConvert }),
                    BindingFlags.Instance | BindingFlags.Public,
                    binder: null,
                    args: null,
                    culture: null)!;
        }
    }


    /// <summary>
    /// Converts a <see cref="VerificationRelationship"/> to or from JSON.
    /// </summary>
    /// <typeparam name="TVerificationRelationship">The type of <see cref="VerificationRelationship"/> to convert.</typeparam>
    public class VerificationRelationshipConverter<TVerificationRelationship>: JsonConverter<TVerificationRelationship> where TVerificationRelationship: VerificationRelationship
    {
        /// <inheritdoc/>
        public override TVerificationRelationship Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            //String token type should mean a reference relationship. Object should mean embedded relationship.
            if(reader.TokenType != JsonTokenType.String && reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowJsonException();
            }

            //TODO: Need to add "JwsVerificationKey2020" and handle like verification relationship?
            //This is an extension: https://identity.foundation/sidetree/spec/v0.1.0/
            // https://w3c-ccg.github.io/ld-cryptosuite-registry/
            object? constructorParameter = null;
            if(reader.TokenType == JsonTokenType.String)
            {
                constructorParameter = reader.GetString() ?? string.Empty;
            }
            else if(reader.TokenType == JsonTokenType.StartObject)
            {
                var newOptions = new JsonSerializerOptions
                {
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                    PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase })),
                    Converters =
                    {
                        new VerificationMethodConverter()
                    }
                };

                constructorParameter = JsonSerializer.Deserialize<VerificationMethod>(ref reader, options);
            }
            else
            {
                ThrowHelper.ThrowJsonException("Unexpected JSON token type.");
            }

            //Different verification relationships enable the associated verification methods to be used for different purposes.
            //The data content is the same, but the relationship is named and has some additional rules.
            return (TVerificationRelationship)Activator.CreateInstance(typeof(TVerificationRelationship), new object[] { constructorParameter! })!;
        }


        /// <inheritdoc/>
        public override void Write(Utf8JsonWriter writer, TVerificationRelationship value, JsonSerializerOptions options)
        {
            var converter = GetKeyConverter<VerificationMethod>(options);
            var verification = (VerificationRelationship)value;

            if(verification.EmbeddedVerification != null && verification.IsEmbeddedVerification)
            {
                //TODO: Fix this.
#pragma warning disable CS8604 // Possible null reference argument.
                converter.Write(writer, value.EmbeddedVerification, options);
#pragma warning restore CS8604 // Possible null reference argument.
            }
            else if(!verification.IsEmbeddedVerification)
            {
                writer.WriteStringValue(verification.VerificationReferenceId);
            }
        }


        private static JsonConverter<TVerificationMethod> GetKeyConverter<TVerificationMethod>(JsonSerializerOptions options) where TVerificationMethod: VerificationMethod
        {
            return (JsonConverter<TVerificationMethod>)options.GetConverter(typeof(TVerificationMethod));
        }
    }
}
