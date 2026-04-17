using DataSchema;
using Microsoft.AspNetCore.Mvc;
using SQLiScanner.API.Services;

namespace SQLiScanner.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class AnalyzeController : ControllerBase
    {
        private readonly GeminiAnalyzerService _geminiService;
        private readonly ILogger<AnalyzeController> _logger;
        public AnalyzeController(GeminiAnalyzerService geminiService, ILogger<AnalyzeController> logger)
        {
            _geminiService = geminiService;
            _logger = logger;
        }

        // Tạo endpoint POST tại đường dẫn: api/analyze/context
        [HttpPost("context")]
        public async Task<IActionResult> AnalyzeContext([FromBody] AiContextRequestPayload payload)
        {
            _logger.LogInformation($"[NHẬN REQUEST] Đang phân tích URL: {payload.Url}");

            if (payload == null || string.IsNullOrWhiteSpace(payload.Url))
            {
                _logger.LogWarning("Payload rỗng hoặc thiếu URL!");
                return BadRequest(new AiContextResponse(false, "Payload không hợp lệ hoặc thiếu Target URL."));
            }

            try
            {
                AiContextResponse result = await _geminiService.AnalyzeAsync(payload);
                _logger.LogInformation($"[KẾT QUẢ AI] Có lỗi SQLi không: {result.IsVulnerable} - Lý do: {result.Reason}");
                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new AiContextResponse(false, $"Lỗi máy chủ API: {ex.Message}"));
            }

        }

    }
}
