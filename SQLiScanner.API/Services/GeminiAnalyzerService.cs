using DataSchema;
using Microsoft.Extensions.Configuration;
using SQLiScanner.API.Models;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
namespace SQLiScanner.API.Services
{
    public class GeminiAnalyzerService
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private readonly string _baseUrl;
        private readonly string _model;

        public GeminiAnalyzerService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;

            _apiKey = configuration["GeminiAi:ApiKey"] ?? throw new ArgumentNullException("Thiếu cấu hình GeminiAi:ApiKey");
            _baseUrl = configuration["GeminiAi:BaseUrl"] ?? "https://generativelanguage.googleapis.com/v1beta/models/";
            _model = configuration["GeminiAi:Model"] ?? "gemini-2.5-flash";
        }

        
        public async Task<AiContextResponse> AnalyzeAsync(AiContextRequestPayload payload)
        {
            try
            {
                string prompt = BuildPrompt(payload);
                var geminiRequestBody = new GeminiRequest
                {
                    Contents = new List<GeminiRequestContent>
                    {
                        new GeminiRequestContent
                        {
                            Parts = new List<GeminiRequestPart>
                            {
                                new GeminiRequestPart {Text  = prompt}
                            }
                        }
                    },
                    GenerationConfig = new GeminiGenerationConfig { ResponseMimeType = "application/json" }
                };

                string requestUrl = $"{_baseUrl}{_model}:generateContent?key={_apiKey}";
                var response = await _httpClient.PostAsJsonAsync(requestUrl, geminiRequestBody);

                if (!response.IsSuccessStatusCode)
                {
                    string errorText = await response.Content.ReadAsStringAsync();
                    return new AiContextResponse(false, $"Lỗi từ Google API: {response.StatusCode} - {errorText}");
                }

                var geminiResponse = await response.Content.ReadFromJsonAsync<GeminiRawResponse>();
                string? jsonResult = geminiResponse?.Candidates?[0]?.Content?.Parts?[0]?.Text;

                if (string.IsNullOrEmpty(jsonResult))
                {
                    return new AiContextResponse(false, "Gemini không trả về kết quả.");
                }

                var finalResult = JsonSerializer.Deserialize<AiContextResponse>(
                    jsonResult,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );

                return finalResult ?? new AiContextResponse(false, "Không thể Deserialize JSON từ Gemini.");
            }
            catch (Exception ex)
            {
                return new AiContextResponse(false, $"Lỗi trong quá trình xử lý AI: {ex.Message}");
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private string BuildPrompt(AiContextRequestPayload payload)
        {
            return $@"Bạn là một chuyên gia bảo mật ứng dụng Web (Cybersecurity Expert).
                    Nhiệm vụ của bạn là phân tích hai đoạn HTML (trước và sau khi chèn payload SQL Injection) để xác định xem trang web có bị lỗi SQL Injection hay không.

                    Thông tin Request:
                    - Target URL: {payload.Url}
                    - Page Title: {payload.PageTitle}
                    - CSS Path khu vực bị thay đổi: {payload.CssPath}

                    [HTML TRƯỚC KHI CHÈN PAYLOAD (BASE)]
                    {payload.HtmlBefore}

                    [HTML SAU KHI CHÈN PAYLOAD (FALSE REQUEST)]
                    {payload.HtmlAfter}

                    Dựa trên sự khác biệt HTML tại CSS Path trên, hãy xác định xem đây có phải là dấu hiệu của SQL Injection không (VD: mất dữ liệu, lộ lỗi SQL syntax, v.v). Nếu chỉ là thay đổi do token động, thời gian hoặc lỗi server chung chung, hãy coi là False Positive (Safe).

                    BẮT BUỘC trả về duy nhất một object JSON hợp lệ theo định dạng sau (không giải thích thêm, không dùng markdown ```json):
                    {{
                        ""isVulnerable"": true hoặc false,
                        ""reason"": ""Giải thích ngắn gọn lý do tại sao lại có kết luận như vậy dựa trên khác biệt của 2 đoạn HTML""
                    }}";
        }
    }
}