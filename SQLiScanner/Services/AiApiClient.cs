using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
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
            // DEBUG
            //var jsonDebug = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true});
            //await File.WriteAllTextAsync("payload_debug.json", jsonDebug);
            //await Task.Delay(5000);
            //return new AiContextResponse(true, "Mock Result");
            try
            {
                HttpResponseMessage response = await _httpClient.PostAsJsonAsync("api/analyze/context", payload);

                if (response.IsSuccessStatusCode)
                {
                    AiContextResponse? result = await response.Content.ReadFromJsonAsync<AiContextResponse>();

                    return result ?? new AiContextResponse(false, "API trả về dữ liệu rỗng hoặc không đúng format JSON.");
                }
                return new AiContextResponse(false, $"Lỗi API Server: {response.StatusCode}");
            }
            catch (HttpRequestException ex)
            {
                return new AiContextResponse(false, "Không thể kết nối đến AI Server.");
            }
            catch (TaskCanceledException)
            {
                // Lỗi quá thời gian chờ (Timeout)
                return new AiContextResponse(false, "AI API phản hồi quá lâu (Timeout).");
            }
        }
    }
}