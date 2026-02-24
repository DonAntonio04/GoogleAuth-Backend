using System.Text.Json.Serialization;

namespace GoogleAuth_Backend.Models
{
    public class EncryptedPayload
    {
        [JsonPropertyName("Data")]
        public string Data { get; set; }
    }
}