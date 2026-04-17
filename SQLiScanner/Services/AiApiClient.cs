using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using DataSchema;
using SQLiScanner.Utility;

namespace SQLiScanner.Services
{
    public class AiApiClient : IAiApiClient
    {
        private readonly HttpClient _httpClient;
        public AiApiClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }
        public async Task<AiContextResponse> AnalyzeSqlInjectionAsync(AiContextRequestPayload payload)
        {
            try
            {
                HttpResponseMessage response = await _httpClient.PostAsJsonAsync("api/analyze/context", payload);

                if (response.IsSuccessStatusCode)
                {
                    AiContextResponse? result = await response.Content.ReadFromJsonAsync<AiContextResponse>();

                    return result ?? new AiContextResponse(false, "API trả về dữ liệu rỗng hoặc không đúng format JSON.");
                }

                Logger.Error($"API Server trả về lỗi: {response.StatusCode}");
                return new AiContextResponse(false, $"Lỗi API Server: {response.StatusCode}");
            }
            catch (HttpRequestException ex)
            {
                Logger.Error($"Lỗi mạng khi kết nối tới AI API: {ex.Message}");
                return new AiContextResponse(false, "Không thể kết nối đến AI Server.");
            }
            catch (TaskCanceledException)
            {
                // Lỗi quá thời gian chờ (Timeout)
                Logger.Error("Request tới AI API bị Timeout.");
                return new AiContextResponse(false, "AI API phản hồi quá lâu (Timeout).");
            }
        }
    }
}