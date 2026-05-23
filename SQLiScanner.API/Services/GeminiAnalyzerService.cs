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
        private readonly string _primaryModel;
        private readonly string _fallbackModel;
        private readonly ResiliencePipeline _pipeline;
        public GeminiAnalyzerService(ResiliencePipelineProvider<string> pipelineProvider, IConfiguration configuration)
        {
            _pipeline = pipelineProvider.GetPipeline("GeminiRetryPipeline");
            _apiKey = configuration["GeminiAi:ApiKey"] ?? throw new ArgumentNullException("Thiếu cấu hình GeminiAi:ApiKey");

            _primaryModel = configuration["GeminiAi:Model"] ?? "gemini-2.5-flash";
            _fallbackModel = configuration["GeminiAi:FallbackModel"] ?? "gemini-2.5-flash-lite";
        }

        public async Task<AiContextResponse> AnalyzeAsync(AiContextRequestPayload payload)
        {
            string prompt = BuildPrompt(payload);

            try
            {
                //Thử model chính trước (Gemini 2.5 Flash)
                return await ExecuteModelAsync(_primaryModel, prompt);
            }
            catch (Exception ex) when (ShouldTriggerFallback(ex))
            {
                //Nếu lỗi do Quá tải (429) hoặc Ngắt mạch (Circuit Open), kích hoạt Fallback
                try
                {
                    return await ExecuteModelAsync(_fallbackModel, prompt);
                }
                catch (Exception fallbackEx)
                {
                    // Nếu cả dự phòng cũng chết thì coi như trả reponse False
                    var actualFallbackEx = fallbackEx is AggregateException agg 
                        ? agg.Flatten().InnerException ?? agg 
                        : fallbackEx;
                    return HandleApiError(actualFallbackEx, _fallbackModel);
                }
            }
            catch (Exception ex)
            {
                var actualEx = ex is AggregateException agg 
                    ? agg.Flatten().InnerException ?? agg 
                    : ex;
                return HandleApiError(actualEx, _primaryModel);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private string BuildPrompt(AiContextRequestPayload payload)
        {
            return $@"Bạn là chuyên gia kiểm thử bảo mật (Pentester). Phân tích bối cảnh sau khi dùng kĩ thuật Boolean-Based để xác định lỗ hổng SQL Injection.

                    Thông tin Request:
                    - Target URL: {payload.TargetUrl}
                    - Page Title: {payload.PageTitle}
                    
                    DẤU HIỆU ĐỊNH TUYẾN (CỰC KỲ QUAN TRỌNG CHO AUTH BYPASS):
                    - URL sau khi chèn payload luôn đúng: {payload.TrueUrl}
                    - URL sau khi chèn payload luôn sai: {payload.FalseUrl}
                    (*) CHÚ Ý: Nếu URL sau khi chèn bị thay đổi (Redirect sang trang quản trị, dashboard, index, v.v.) trong khi URL ban đầu là trang Login/Xác thực, đây là DẤU HIỆU MẠNH của lỗi Authentication Bypass.

                    BỐI CẢNH HTML TẠI KHU VỰC THAY ĐỔI:
                    - Vị trí (CSS Path): {payload.CssPath}
                    - HTML payload luôn đúng: {payload.TrueHtml}
                    - HTML payload luôn sai: {payload.FalseHtml}
                    
                    TIÊU CHÍ PHÂN TÍCH:
                    1. URL Redirect: Có sự chuyển hướng bất thường nào thể hiện việc đăng nhập thành công hay vượt quyền không?
                    2. Dấu hiệu Database: Có lộ lỗi syntax SQL (Error-based) hay mất mát/thay đổi dữ liệu rõ rệt do logic True/False (Boolean-based) không?
                    3. False Positive: Nếu thay đổi chỉ là mã token (CSRF), thời gian, session ID, hoặc thông báo lỗi server chung chung (VD: 404, 403) không liên quan đến DB, hãy đánh giá là an toàn (False Positive).

                    Dựa vào các tiêu chí trên, hãy đưa ra quyết định cuối cùng.";
        }

        private async Task<AiContextResponse> ExecuteModelAsync(string targetModel, string prompt)
        {
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
                (client, model: targetModel, prompt, config)
            );

            if (response == null || string.IsNullOrEmpty(response.Text))
            {
                throw new InvalidOperationException("Gemini không trả về kết quả nội dung.");
            }

            var finalResult = JsonSerializer.Deserialize<AiContextResponse>(
                response.Text,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            );

            return finalResult ?? throw new InvalidOperationException("Không thể Deserialize JSON từ Gemini.");
        }

        private AiContextResponse HandleApiError(Exception ex, string modelName)
        {
            if (ex is BrokenCircuitException)
                return new AiContextResponse(false, $"[CIRCUIT OPEN - {modelName}] API đang bị quá tải liên tục. Vui lòng thử lại sau.");

            if (ex.GetType().Name.Contains("Api") || ex.GetType().Name.Contains("Client"))
                return new AiContextResponse(false, $"Lỗi API Google ({modelName}): {ex.Message}");

            return new AiContextResponse(false, $"Lỗi xử lý AI ({modelName}): {ex.Message}");
        }

        private bool ShouldTriggerFallback(Exception ex)
        {
            if (ex is AggregateException aggregateException)
            {
                ex = aggregateException.Flatten().InnerException ?? aggregateException;
            }

            if (ex is BrokenCircuitException) return true;

            string msg = ex.Message.ToLower();
            if (!string.IsNullOrEmpty(msg))
            {
                if (msg.Contains("429", StringComparison.OrdinalIgnoreCase) ||
                    msg.Contains("503", StringComparison.OrdinalIgnoreCase) ||
                    msg.Contains("500", StringComparison.OrdinalIgnoreCase) ||
                    msg.Contains("high demand", StringComparison.OrdinalIgnoreCase) ||
                    msg.Contains("too many requests", StringComparison.OrdinalIgnoreCase) ||
                    msg.Contains("quota exceeded", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            try
            {
                var statusCodeProp = ex.GetType().GetProperty("StatusCode");
                if (statusCodeProp != null)
                {
                    var statusCodeVal = statusCodeProp.GetValue(ex);
                    if (statusCodeVal != null)
                    {
                        int code = (int)statusCodeVal;
                        return code == 429 || code == 503 || code == 500;
                    }
                }
            }
            catch { }

            if (ex is HttpRequestException httpEx && httpEx.StatusCode.HasValue)
            {
                int code = (int)httpEx.StatusCode.Value;
                return code == 429 || code == 503 || code == 500;
            }
            return false;
        }
    }
}