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
    {
        if (ex is TaskCanceledException || ex is TimeoutException) return true;

        string msg = ex.Message;
        return msg.Contains("408") ||
               msg.Contains("429") ||
               msg.Contains("500") ||
               msg.Contains("502") ||
               msg.Contains("503") ||
               msg.Contains("504");
    });

    pipelineBuilder.AddRetry(new RetryStrategyOptions
    {
        ShouldHandle = isTransientError,
        MaxRetryAttempts = 4,
        BackoffType = DelayBackoffType.Exponential,
        Delay = TimeSpan.FromSeconds(1),
        MaxDelay = TimeSpan.FromSeconds(60),
        UseJitter = true //Rất quan trọng để tránh "Thundering Herd" (nhiều luồng cùng gửi lại 1 lúc làm sập tiếp API)
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

    // Thêm Timeout tổng quát cho toàn bộ Pipeline
    pipelineBuilder.AddTimeout(TimeSpan.FromMinutes(2));
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
