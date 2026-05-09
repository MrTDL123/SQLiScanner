using Microsoft.Extensions.Http.Resilience;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;
using SQLiScanner.API.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Đăng ký Service & Tích hợp Resilient (Retry và Exponential Backoff)
builder.Services.AddResiliencePipeline("GeminiRetryPipeline", pipelineBuilder =>
{
    var isTransientError = new PredicateBuilder().Handle<Exception>(ex =>
            ex is HttpRequestException ||
            ex is TaskCanceledException || // Lỗi Timeout mạng
            ex.Message.Contains("429") ||  // Too Many Requests
            ex.Message.Contains("50")      // Lỗi 500, 503 từ server Google
    );

    pipelineBuilder.AddRetry(new RetryStrategyOptions
    {
        MaxRetryAttempts = 3,
        BackoffType = DelayBackoffType.Exponential,
        Delay = TimeSpan.FromSeconds(1),
        // Đảm bảo chỉ Retry khi cần thiết
        ShouldHandle = isTransientError
    });

    pipelineBuilder.AddCircuitBreaker(new CircuitBreakerStrategyOptions
    {
        // Điều kiện lỗi để ngắt mạch nếu xảy ra quá nhiều
        ShouldHandle = isTransientError,
        FailureRatio = 0.5,
        SamplingDuration = TimeSpan.FromMinutes(1),
        // Phải có ít nhất 5 request trong 1p thì mới ngắt mạch
        MinimumThroughput = 5,
        BreakDuration = TimeSpan.FromSeconds(30)
    });
});


// Đăng ký Service phân tích ngữ nghĩa 
builder.Services.AddScoped<GeminiAnalyzerService>();
builder.Services.AddScoped<IResponseSimilarityService, ResponseSimilarityService>();


// Logging 
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var app = builder.Build();

app.UseHttpsRedirection();
app.MapControllers();


app.Run();
