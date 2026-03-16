using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Models
{
    // Kết quả phân tích Context hoàn chỉnh
    public class ContextAnalysisResult
    {
        public string ParameterType { get; set; }

        public List<Boundary> ApplicableBoundaries { get; set; } = new();

        public List<PayloadTest> ApplicablePayloads { get; set; } = new();

        // Boundary được chốt - dùng cho các giai đoạn sau
        public Boundary? LockedBoundary { get; set; }

        // Prefix cuối cùng sẽ dùng nếu như các prefix khác không thành công
        public string FinalPrefix { get; set; }

        // Prefix cuối cùng sẽ dùng nếu như các prefix khác không thành công
        public string FinalSuffix { get; set; }

        public string FinalComment { get; set; }

        // Độ tin cậy của kết quả phân tích Context
        public int ConfidenceScore { get; set; }

        public string ErrorMessage { get; set; }

        public override string ToString()
        {
            var status = string.IsNullOrEmpty(ErrorMessage) ? "SUCCESS" : "FAILED";
            return $"[{status}] {ParameterType} | Confidence:{ConfidenceScore} | Boundaries:{ApplicableBoundaries.Count} | Payloads:{ApplicablePayloads.Count}";
        }
    }
}
