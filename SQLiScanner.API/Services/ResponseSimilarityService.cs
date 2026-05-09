using HtmlAgilityPack;
using Mscc.GenerativeAI;
using SQLiScanner.API.Models;
using System.Text;
using System.Text.RegularExpressions;

namespace SQLiScanner.API.Services
{
    /// <summary>
    /// Service đo độ tương đồng giữa 2 nội dung HTTP Response.
    /// Áp dụng Jaccard Similarity cho các trường hợp rõ ràng (Fast Path)
    /// và Google Gemini AI cho các trường hợp cần phân tích ngữ nghĩa sâu.
    /// </summary>
    public class ResponseSimilarityService : IResponseSimilarityService
    {
        private readonly IConfiguration _config;
        private readonly ILogger<ResponseSimilarityService> _logger;

        public ResponseSimilarityService(
            IConfiguration config,
            ILogger<ResponseSimilarityService> logger)
        {
            _config = config;
            _logger = logger;
        }

        public async Task<SimilarityResponse> AnalyzeAsync(SimilarityRequest request)
        {
            string htmlA = request.ContentA;
            string htmlB = request.ContentB;

            string textA = ExtractCleanText(htmlA);
            string textB = ExtractCleanText(htmlB);

            double jaccardScore = CalculateJaccard(textA, textB);
            _logger.LogInformation("Jaccard similarity: {Score:F3}", jaccardScore);

            // Fast Path: Nếu cực kỳ giống nhau hoặc cực kỳ khác nhau, trả về luôn không cần dùng AI
            if (jaccardScore >= 0.92 || jaccardScore <= 0.45)
            {
                _logger.LogInformation("Fast path hit! Trả về dựa trên Jaccard Score: {Score:P1}", jaccardScore);
                return new SimilarityResponse { SimilarityScore = jaccardScore };
            }

            // Deep Semantic Analysis: Gọi Gemini
            _logger.LogInformation("Jaccard ở vùng uncertain ({Score:F3}), gọi Gemini AI để phân tích ngữ nghĩa...", jaccardScore);
            return await AnalyzeWithGeminiAsync(textA, textB, jaccardScore);
        }

        private async Task<SimilarityResponse> AnalyzeWithGeminiAsync(
            string textA, string textB, double fallbackJaccardScore)
        {
            try
            {
                string apiKey = _config["Gemini:ApiKey"]
                    ?? throw new InvalidOperationException("Gemini:ApiKey chưa được cấu hình.");

                if (string.IsNullOrWhiteSpace(apiKey))
                    throw new InvalidOperationException("API Key trống.");

                var googleAI = new GoogleAI(apiKey);
                var model = googleAI.GenerativeModel("gemini-1.5-flash");

                string truncA = textA.Length > 3000 ? textA[..3000] + "..." : textA;
                string truncB = textB.Length > 3000 ? textB[..3000] + "..." : textB;

                string prompt = $$"""
                    Hãy đóng vai trò là một chuyên gia phân tích dữ liệu và cấu trúc website.
                    Tôi có 2 đoạn nội dung (đã được trích xuất từ 2 trang web khác nhau).
                    Hãy phân tích và cho tôi biết 2 đoạn nội dung này giống nhau bao nhiêu phần trăm về mặt ngữ nghĩa và hiển thị tổng thể?

                    === NỘI DUNG A ===
                    {{truncA}}

                    === NỘI DUNG B ===
                    {{truncB}}

                    Yêu cầu:
                    - TRẢ LỜI CHÍNH XÁC duy nhất một con số hệ thập phân (từ 0.0 đến 1.0) biểu thị % độ tương đồng.
                    - KHÔNG in ra bất kỳ chữ hoặc ký tự nào khác (kể cả dấu ngoặc hay giải thích).
                    Ví dụ: 0.85
                    """;

                var geminiResponse = await model.GenerateContent(prompt);
                string rawResult = geminiResponse.Text?.Trim() ?? string.Empty;
                rawResult = Regex.Replace(rawResult, @"[^0-9\.]", ""); // Lọc sạch lấy số

                if (double.TryParse(rawResult, out double similarityScore))
                {
                    similarityScore = Math.Clamp(similarityScore, 0.0, 1.0);
                    _logger.LogInformation("Gemini AI similarity score: {Score:F3}", similarityScore);
                    return new SimilarityResponse { SimilarityScore = similarityScore };
                }

                _logger.LogWarning("Gemini trả về chuỗi không thể convert thành số ({Result}). Fallback Jaccard.", rawResult);
                return new SimilarityResponse { SimilarityScore = fallbackJaccardScore };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Lỗi gọi AI (có thể hết Quota). Fallback về Jaccard.");
                return new SimilarityResponse { SimilarityScore = fallbackJaccardScore };
            }
        }

        private string ExtractCleanText(string html)
        {
            if (string.IsNullOrWhiteSpace(html)) return string.Empty;
            var doc = new HtmlDocument();
            doc.LoadHtml(html);

            var nodesRemove = doc.DocumentNode
                .SelectNodes("//script|//style|//comment()")
                ?? Enumerable.Empty<HtmlNode>();

            foreach (var node in nodesRemove.ToList()) node.Remove();

            string text = doc.DocumentNode.InnerText;
            return Regex.Replace(text, @"\s+", " ").Trim();
        }

        private double CalculateJaccard(string text1, string text2)
        {
            if (string.IsNullOrWhiteSpace(text1) && string.IsNullOrWhiteSpace(text2)) return 1.0;
            if (string.IsNullOrWhiteSpace(text1) || string.IsNullOrWhiteSpace(text2)) return 0.0;
            if (text1 == text2) return 1.0;

            var set1 = new HashSet<string>(text1.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            var set2 = new HashSet<string>(text2.Split(' ', StringSplitOptions.RemoveEmptyEntries));

            int intersection = set1.Intersect(set2).Count();
            int union = set1.Union(set2).Count();

            return union == 0 ? 0.0 : (double)intersection / union;
        }
    }
}
