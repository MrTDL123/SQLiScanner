using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SQLiScanner;
using SQLiScanner.Modules;
using SQLiScanner.Services;
using System;
using System.Threading.Tasks;

namespace SQLiScanner
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var services = new ServiceCollection();

            Action<HttpClient> defaultWebClientConfig = client =>
            {
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                client.Timeout = TimeSpan.FromSeconds(30);
            };

            services.AddHttpClient<Crawler>(defaultWebClientConfig);
            services.AddHttpClient<ContextAnalyzer>(defaultWebClientConfig);
            services.AddHttpClient<DatabaseDetector>(defaultWebClientConfig);
            services.AddHttpClient<UnionDetector>(defaultWebClientConfig);

            services.AddHttpClient<IAiApiClient, AiApiClient>(client =>
            {
                client.BaseAddress = new Uri("https://localhost:5001/");
                client.Timeout = TimeSpan.FromSeconds(60);
            });

            services.AddTransient<ScannerApp>();
            var serviceProvider = services.BuildServiceProvider();

            try
            {
                var app = serviceProvider.GetRequiredService<ScannerApp>();
                await app.RunAsync();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Lỗi hệ thống nghiêm trọng: {ex.Message}");
                Console.ResetColor();
            }

        }

    }
}
