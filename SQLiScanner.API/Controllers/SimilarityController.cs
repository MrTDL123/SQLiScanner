using Microsoft.AspNetCore.Mvc;
using SQLiScanner.API.Models;
using SQLiScanner.API.Services;

namespace SQLiScanner.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SimilarityController : ControllerBase
    {
        private readonly IResponseSimilarityService _similarityService;
        private readonly ILogger<SimilarityController> _logger;

        public SimilarityController(
            IResponseSimilarityService similarityService,
            ILogger<SimilarityController> logger)
        {
            _similarityService = similarityService;
            _logger = logger;
        }

        /// <summary>
        /// Phân tích 2 đoạn nội dung (HTML hoặc Text) để phát hiện mức độ tương đồng.
        /// </summary>
        /// <remarks>
        /// Ví dụ request body:
        ///
        ///     POST /api/similarity/analyze
        ///     {
        ///         "contentA": "<html><body>Hello</body></html>",
        ///         "contentB": "<html><body>Hello World</body></html>"
        ///     }
        ///
        /// </remarks>
        [HttpPost("analyze")]
        [ProducesResponseType(typeof(SimilarityResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Analyze([FromBody] SimilarityRequest request)
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(request.ContentA) || string.IsNullOrWhiteSpace(request.ContentB))
            {
                return BadRequest(new { error = "ContentA và ContentB không được để trống." });
            }

            _logger.LogInformation("Nhận request phân tích tương đồng. ContentA length: {LenA}, ContentB length: {LenB}",
                request.ContentA.Length, request.ContentB.Length);

            var result = await _similarityService.AnalyzeAsync(request);

            if (result.Error != null)
            {
                return StatusCode(StatusCodes.Status503ServiceUnavailable, result);
            }

            return Ok(result);
        }

        /// <summary>
        /// Kiểm tra API còn sống không.
        /// </summary>
        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(new { status = "OK", timestamp = DateTime.UtcNow });
        }
    }
}
