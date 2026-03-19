using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Models
{
    public class HeuristicResult
    {
        // Giá trị tham số
        // Giá trị: "INTEGER", "STRING_SINGLE_QUOTE", 
        // "LIKE_SINGLE_QUOTE", "NESTED_PARENTHESIS", "UNKNOWN"
        public string DetectedType { get; set; }

        // Đại diện độ tương đồng giữa 2 response heuristic 
        // Ví dụ: kiểm tra độ tương đồng giữa tham số id=1234-1 và id=1233
        // Nếu > 95% → có khả năng Integer
        // Nếu < 50% → có khả năng String/LIKE/Nested
        public double Similarity { get; set; }

        // Điểm tin cậy (0-100)
        public int ConfidenceScore { get; set; }

        // Những boundary khả thi sau khi xác định type
        public List<Boundary> ApplicableBoundaries { get; set; } = new();

        // Boundary hoạt động được thu nhặt từ Phase 3 ở ContextAnalyzer
        public Boundary LockedBoundary { get; set; }

        // Tạo một thuộc tính để nhận prefix từ locked boundary cho tiện truy vấn
        public string WorkingPrefix
        {
            get => LockedBoundary?.Prefix ?? "";
        }

        public string WorkingSuffix
        {
            get => LockedBoundary?.Suffix ?? "";
        }

        public string WorkingComment
        {
            get
            {
                if (LockedBoundary == null)
                    return "--";

                // Infer comment từ suffix
                if (LockedBoundary.Suffix.Contains("#"))
                    return "#";
                if (LockedBoundary.Suffix.Contains("--"))
                    return "--";

                // Default
                return "--";
            }
        }

        public List<PayloadTest> ApplicablePayloads { get; set; } = new();

        // Giá trị:
        //   - "SUCCESS" = Đã lock boundary & load payloads
        //   - "UNCERTAIN" = Không chắc chắn, cần thử all boundaries
        //   - "FAILED" = Không phát hiện được gì
        public string Status { get; set; } = "UNCERTAIN";

        // HELPER METHOD
        // Đã có boundary được xác nhạn
        public bool HasLockedBoundary => LockedBoundary != null;
        public bool HasPayloads => ApplicablePayloads?.Count > 0;
        public bool HasBoundaries => ApplicableBoundaries?.Count > 0 || HasLockedBoundary;
        public bool IsReadyForDetection => HasPayloads && HasBoundaries;

        public string GetLockedBoundaryInfo()
        {
            if (!HasLockedBoundary) return "Not locked";
            return $"Ngữ cảnh: {LockedBoundary.ContextName} | " +
                   $"Prefix: '{LockedBoundary.Prefix}' | " +
                   $"Suffix: '{LockedBoundary.Suffix}'";
        }
    }
}
