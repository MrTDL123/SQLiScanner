using Microsoft.Extensions.DependencyInjection;
using SQLiScanner;
using SQLiScanner.Modules;
using SQLiScanner.Services;
using SQLiScanner.Utility;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using Polly;
using Polly.Retry;
using Polly.RateLimiting;
using Microsoft.Extensions.Http.Resilience;


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

            var sharedCookieContainer = new CookieContainer();
            // Nếu quét nhiều website cùng lúc có thể sẽ bị lẫn cookie lẫn nhau
            services.AddSingleton(sharedCookieContainer);

            Action<ResiliencePipelineBuilder<HttpResponseMessage>> configureResilience = builder =>
            {
                builder.AddRateLimiter(new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
                {
                    TokenLimit = 10,
                    QueueLimit = 100,
                    ReplenishmentPeriod = TimeSpan.FromSeconds(2),
                    TokensPerPeriod = 10,
                    AutoReplenishment = true
                }));

                builder.AddRetry(new RetryStrategyOptions<HttpResponseMessage>
                {
                    ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                        .Handle<HttpRequestException>()
                        .Handle<TimeoutException>()
                        .HandleResult(response => response.StatusCode == HttpStatusCode.TooManyRequests    // 429
                                               || response.StatusCode == HttpStatusCode.ServiceUnavailable // 503
                                               || response.StatusCode == HttpStatusCode.BadGateway         // 502: Nginx mất kết nối với Backend
                                               || response.StatusCode == HttpStatusCode.GatewayTimeout),   // 504    
                                                
                    MaxRetryAttempts = 3,
                    BackoffType = DelayBackoffType.Exponential,
                    UseJitter = true,
                    Delay = TimeSpan.FromSeconds(2),
                    OnRetry = arguments =>
                    {
                        return ValueTask.CompletedTask;
                    }
                });
            };
            
            services.AddHttpClient<IRequestDispatcher, RequestDispatcher>(defaultWebClientConfig)
                    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
                    {
                        UseCookies = false,
                        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                        PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
                        // TODO: Cần phải đổi nếu như sau này tích hợp thêm đa luồng
                        MaxConnectionsPerServer = 200,
                        AutomaticDecompression = DecompressionMethods.All
                    })
                    .SetHandlerLifetime(Timeout.InfiniteTimeSpan)
                    .AddResilienceHandler("SqliResilience", configureResilience);

            services.AddHttpClient<Crawler>(defaultWebClientConfig)
                    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
                    {
                        UseCookies = true,
                        CookieContainer = sharedCookieContainer, 
                        AllowAutoRedirect = true,
                        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                        PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
                        MaxConnectionsPerServer = 100,
                        AutomaticDecompression = DecompressionMethods.All
                    })
                    .SetHandlerLifetime(Timeout.InfiniteTimeSpan)
                    .AddResilienceHandler("SqliResilience", configureResilience);

            services.AddHttpClient<IAiApiClient, AiApiClient>(client =>
                {
                    client.BaseAddress = new Uri("https://localhost:7236/");
                    client.Timeout = TimeSpan.FromSeconds(60);
                })
                .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
                {
                    PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                    PooledConnectionIdleTimeout = TimeSpan.FromSeconds(60),
                    MaxConnectionsPerServer = 100
                })
                .SetHandlerLifetime(Timeout.InfiniteTimeSpan);


            services.AddTransient<ContextAnalyzer>();
            services.AddTransient<ExploitableAnalyzer>();
            services.AddTransient<UnionDetector>();
            services.AddTransient<ExploitationEngine>();

            services.AddSingleton<AiConcurrencyEngine>();
            services.AddTransient<ScannerApp>();

            var serviceProvider = services.BuildServiceProvider();
            var app = serviceProvider.GetRequiredService<ScannerApp>();

            await app.RunAsync();

        }

    }
}
