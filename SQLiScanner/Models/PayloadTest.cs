using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualBasic;

namespace SQLiScanner.Models
{
    public class PayloadTest
    {
        // Tiêu đề payload
        // Ví dụ: "MySQL >= 5.1 AND error-based - WHERE clause (EXTRACTVALUE)"
        public string Title { get; set; }

        // Loại SQL injection
        // 1 = Boolean-based blind
        // 2 = Error-based
        // 3 = Inline queries
        // 4 = Stacked queries
        // 5 = Time-based blind
        // 6 = UNION query
        // Vì phạm quy dự án nên ta chỉ tập trung vào 1, 2, 5, 6
        public int SType { get; set; }

        // Mức độ phức tạp của Payload
        public int  Level { get; set; }
        
        // Mức độ nguy hiểm của payload cho cơ sỡ dữ liệu đối tượng
        // 1 = Low Risk (read-only)
        // 2 = Medium risk (Khả năng gây quá tải máy chủ)
        // 3 = High risk (có thể làm hỏng dữ liệu)
        public int Risk { get; set; }

        // Đại diện mệnh đề mà Payload đang áp dụng (0-9)
        public string Clause { get; set; }

        // Nơi inject (1-3)
        public int Where { get; set; }

        // Template payload để khai thác dữ liệu sau khi nhận biết có lỗi entry point
        public string Vector { get; set; }

        // Danh sách các payload
        // Với mỗi payload là một biến thể của vector
        public List<string> Payloads { get; set; } = new();

        public string Comment { get; set; }

        // Cho boolean-based: Payload để compare (dùng để test TRUE/FALSE)
        public string ComparisonPayload { get; set; }

        // Cho error-based: Regex để extract kết quả từ error message
        public string ErrorResponsePattern { get; set; }
 
         // Cho time-based: Thời gian delay mong đợi (seconds)
        public int? TimeDelay { get; set; }

        // Database type mà payload support
        public string DBMS { get; set; }

        // Phiên bản database
        public string DBMSVersion { get; set; }

        public override string ToString()
        {
            return $"[{DBMS}] {Title} (Level:{Level}, Risk:{Risk})";
        }
    }
}
