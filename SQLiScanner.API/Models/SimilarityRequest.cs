namespace SQLiScanner.API.Models
{
    /// <summary>
    /// Request gửi vào API: 2 URL cần so sánh
    /// </summary>
    public class SimilarityRequest
    {
        /// <summary>Nội dung website thứ nhất (A) - dạng HTML hoặc Text</summary>
        public string ContentA { get; set; } = string.Empty;

        /// <summary>Nội dung website thứ hai (B) - dạng HTML hoặc Text</summary>
        public string ContentB { get; set; } = string.Empty;
    }

    /// <summary>
    /// Kết quả trả về từ API
    /// </summary>
    public class SimilarityResponse
    {
        /// <summary>Điểm tương đồng (0.0 = hoàn toàn khác, 1.0 = giống hệt)</summary>
        public double SimilarityScore { get; set; }

        /// <summary>Thông báo lỗi nếu có (nếu thành công thì null)</summary>
        public string? Error { get; set; }
    }
}
