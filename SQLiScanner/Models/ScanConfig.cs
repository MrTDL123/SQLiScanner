using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Models
{
    public class ScanConfig
    {
        // Cấu hình: Dùng ngay link đang phân tích khi phát hiện lỗ hổng
        public bool ExitOnFirstHit { get; set; }

        // Dùng để phát tìn hiệu hủy (Dành cho Early Exit hoặc thoát thủ công)
        public CancellationTokenSource Cts { get; set; }
        public CancellationToken Token => Cts.Token;
        public ConcurrentBag<DetectionResult> DetectionResults { get; } = new();
        public ScanConfig(bool exitOnFirstHit)
        {
            ExitOnFirstHit = exitOnFirstHit;
            Cts = new CancellationTokenSource();
        }
    }
}
