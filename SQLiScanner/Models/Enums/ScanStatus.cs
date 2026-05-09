namespace SQLiScanner.Models.Enums
{
    public enum ScanStatus
    {
        Pending,           // Đang nằm trong hàng đợi
        HeuristicScanning, // Đang quét nhanh bằng các thuật toán
        AiAnalyzing,       // Rơi vào "vùng xám", đang sử dụng AI để phân tích
        CheckingColumnCount,
        ExploitingData,    
        Dangerous,         // Có khả năng khai thác dữ liệu
        Safe,              // Đã quét xong
        Vulnerable,        // Cảnh báo có lỗ hổng
        Error              // Bị lỗi trong quá trình phân tích
    }
}