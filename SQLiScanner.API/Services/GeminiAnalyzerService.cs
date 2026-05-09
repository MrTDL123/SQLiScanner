using DataSchema;
using Google.GenAI;
using Google.GenAI.Types;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.Extensions.Configuration;
using Polly;
using Polly.CircuitBreaker;
using Polly.Registry;
using SQLiScanner.API.Models;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using Type = Google.GenAI.Types.Type;
namespace SQLiScanner.API.Services
{
    public class GeminiAnalyzerService
    {
        private readonly string _apiKey;
        private readonly string _model;
        private readonly ResiliencePipeline _pipeline;
        public GeminiAnalyzerService(ResiliencePipelineProvider<string> pipelineProvider, IConfiguration configuration)
        {
            _pipeline = pipelineProvider.GetPipeline("GeminiRetryPipeline");
            _apiKey = configuration["GeminiAi:ApiKey"] ?? throw new ArgumentNullException("Thiếu cấu hình GeminiAi:ApiKey");
            _model = configuration["GeminiAi:Model"] ?? "gemini-2.5-flash";
        }

        public async Task<AiContextResponse> AnalyzeAsync(AiContextRequestPayload payload)
        {
            try
            {
                string prompt = BuildPrompt(payload);
                var client = new Client(apiKey: _apiKey);

                var config = new GenerateContentConfig
                {
                    ResponseMimeType = "application/json",
                    Temperature = 0.1,
                    SystemInstruction = new Content
                    {
                        Parts = [
                            new Part {
                                Text = $@"BẮT BUỘC trả về duy nhất một object JSON hợp lệ theo định dạng sau (không giải thích thêm, không dùng markdown ```json):
                                        {{
                                            ""isVulnerable"": true hoặc false,
                                            ""reason"": ""Giải thích ngắn gọn lý do tại sao lại có kết luận như vậy dựa trên khác biệt của 2 đoạn HTML""
                                        }}"
                            }
                        ]
                    },
                    ResponseSchema = new Schema
                    {
                        Type = Type.Object,
                        Properties = new Dictionary<string, Schema>
                        {
                            { "isVulnerable", new Schema { Type = Type.Boolean } },
                            { "reason", new Schema { Type = Type.String } }
                        },
                        Required = ["isVulnerable", "reason"]
                    }
                };

                var response = await _pipeline.ExecuteAsync(
                    static async (state, cancellationToken) =>
                    {
                        return await state.client.Models.GenerateContentAsync(
                            model: state.model,
                            contents: state.prompt,
                            config: state.config
                        );
                    },
                    (client, model: _model, prompt, config)
                );

                if (response == null || string.IsNullOrEmpty(response.Text))
                {
                    return new AiContextResponse(false, "Gemini không trả về kết quả.");
                }

                var finalResult = JsonSerializer.Deserialize<AiContextResponse>(
                    response.Text,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );

                return finalResult ?? new AiContextResponse(false, "Không thể Deserialize JSON từ Gemini.");
            }
            catch (BrokenCircuitException)
            {
                return new AiContextResponse(false, "[CIRCUIT OPEN] API Gemini đang bị lỗi / quá tải liên tục.Đã tạm ngắt mạch để bảo vệ hệ thống.Vui lòng thử lại sau 30 giây.");
            }
            catch (Google.GenAI.ClientError ex)
            {
                return new AiContextResponse(false, $"Lỗi API từ Google: {ex.Message}");
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

                    Dựa trên sự khác biệt HTML tại CSS Path trên, hãy xác định xem đây có phải là dấu hiệu của SQL Injection không (VD: mất dữ liệu, lộ lỗi SQL syntax, v.v). Nếu chỉ là thay đổi do token động, thời gian hoặc lỗi server chung chung, hãy coi là False Positive (Safe).";
        }
    }
}