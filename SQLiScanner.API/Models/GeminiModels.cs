using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace SQLiScanner.API.Models
{
    #region CLASS HỖ TRỢ REQUEST
    public class GeminiRequest
    {
        [JsonPropertyName("contents")]
        public List<GeminiRequestContent> Contents { get; set; } = new();

        [JsonPropertyName("generationConfig")]
        public GeminiGenerationConfig GenerationConfig { get; set; } = new();
    }

    public class GeminiRequestContent
    {
        [JsonPropertyName("parts")]
        public List<GeminiRequestPart> Parts { get; set; } = new();
    }

    public class GeminiRequestPart
    {
        [JsonPropertyName("text")]
        public string Text { get; set; } = string.Empty;
    }

    public class GeminiGenerationConfig
    {
        [JsonPropertyName("responseMimeType")]
        public string ResponseMimeType { get; set; } = "application/json";
        [JsonPropertyName("temperature")]
        public float Temperature { get; set; } = 0.1f;
    }
    #endregion

    #region CLASS HỨNG RESPONSE
    public class GeminiRawResponse
    {
        [JsonPropertyName("candidates")]
        public List<GeminiCandidate>? Candidates { get; set; }
    }

    public class GeminiCandidate
    {
        [JsonPropertyName("content")]
        public GeminiResponseContent? Content { get; set; }
    }

    public class GeminiResponseContent
    {
        [JsonPropertyName("parts")]
        public List<GeminiResponsePart>? Parts { get; set; }
    }

    public class GeminiResponsePart
    {
        [JsonPropertyName("text")]
        public string? Text { get; set; }
    }
    #endregion
}