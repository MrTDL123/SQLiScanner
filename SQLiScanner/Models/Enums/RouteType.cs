
namespace SQLiScanner.Models.Enums
{
    public enum RouteType
    {
        Standard, // Gửi bình thường vào URL/Form
        Cookie,   // Đi cửa sau qua Cookie (HPP)
        Header    // (Dự phòng tương lai) Đi cửa sau qua Header (User-Agent, X-Forwarded-For)
    }
}
