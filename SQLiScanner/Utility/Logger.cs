using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Utility
{
    public static class Logger
    {
        private static int _indentLevel = 0;
        private const int INDENT_SIZE = 3;

        public enum LogLevel
        {
            MainInfo,      // Không indent: thông báo chính
            Phase,         // Indent 1: giai đoạn chính
            Action,        // Indent 2: hành động chi tiết
            Request,       // Indent 3: request/response
            Success,       // Highlight: thành công
            Warning,       // Highlight: cảnh báo
            Error          // Highlight: lỗi
        }

        public static void Process(string message)
        {
            _indentLevel+= 3;
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine(GetIndent() + message);
            Console.ResetColor();
            _indentLevel -= 3;
        }

        public static void Url(string url, string method, string parameters)
        {
            Console.WriteLine("\n");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[URL] " + new string('=', 50));
            Console.ResetColor();
            Console.WriteLine($"URL: {url}");
            Console.WriteLine($"Method: {method.ToUpper()}");
            Console.WriteLine($"Tham số: {parameters}");
            _indentLevel = 0;
        }

        public static void Phase(string name)
        {
            _indentLevel = 1;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine(GetIndent() + $"[GIAI ĐOẠN] {name}");
            Console.ResetColor();
            _indentLevel = 2;
        }

        public static void Info(string message)
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(GetIndent() + $"[*] {message}");
            Console.ResetColor();
        }

        public static void Request(string method, string urlOrData)
        {
            _indentLevel++;
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(GetIndent() + $"→ {method}");
            Console.WriteLine(GetIndent() + $"  {urlOrData}");
            Console.ResetColor();
            _indentLevel--;
        }

        public static void Response(int statusCode, int? length = null, string? additionalInfo = null)
        {
            _indentLevel++;
            Console.ForegroundColor = ConsoleColor.Gray;
            string info = $"← Mã phản hồi: {statusCode}";
            if (length != null) info += $" | Dung lượng: {length} bytes";
            if (additionalInfo != null) info += $" | {additionalInfo}";
            Console.WriteLine(GetIndent() + info);
            Console.ResetColor();
            _indentLevel--;
        }

        public static void Success(string message)
        {
            _indentLevel = Math.Max(0, _indentLevel - 1);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(GetIndent() + $"[+] {message}");
            Console.ResetColor();
            _indentLevel++;
        }

        public static void Warning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(GetIndent() + $"[-] {message}");
            Console.ResetColor();
        }

        public static void Error(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(GetIndent() + $"[ERROR] {message}");
            Console.ResetColor();
        }

        public static void Skipped(string reason)
        {
            _indentLevel = Math.Max(0, _indentLevel - 1);
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(GetIndent() + $"[~] Skipped: {reason}");
            Console.ResetColor();
            _indentLevel++;
        }
        public static void Result(DetectionResult result)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[RESULT] " + new string('=', 50));
            Console.WriteLine($"✓ VULNERABLE");
            Console.WriteLine($"  Database: {result.DatabaseType}");
            Console.WriteLine($"  Vulnerable Param: {result.VulnerableParam}");
            Console.WriteLine($"  Working Prefix: [{result.WorkingPrefix}]");
            Console.WriteLine(new string('=', 58));
            Console.ResetColor();
        }

        private static string GetIndent() => new string(' ', _indentLevel * INDENT_SIZE);
    }
}
