using SQLiScanner.Models.Enums;

namespace SQLiScanner.Models
{
    // Gom nhóm toàn bộ trạng thái định tuyến của Payload
    public readonly struct InjectionRoute
    {
        public RouteType Type { get; }
        // Tên tham số đích sẽ hứng chịu Payload (Ví dụ: tên Cookie ẩn hoặc tên tham số gốc)
        public string TargetKey { get; }
        // Giá trị sạch (Bait Value) gửi qua URL/Form làm mồi qua mặt chữ ký của WAF
        public string OriginalValue { get; }

        public InjectionRoute(RouteType type, string targetKey, string originalValue)
        {
            Type = type;
            TargetKey = targetKey ?? string.Empty;
            OriginalValue = originalValue ?? string.Empty;
        }

        public static InjectionRoute CreateStandard(string paramName, string originalValue)
        {
            return new InjectionRoute(RouteType.Standard, paramName, originalValue);
        }
    }
}
