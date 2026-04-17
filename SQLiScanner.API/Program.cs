using SQLiScanner.API.Services;

var builder = WebApplication.CreateBuilder(args);

// Các Service mặc định của ASP.Net Core
builder.Services.AddControllers();

// ── Đăng ký Service phân tích ngữ nghĩa ──────────────────────────────────
builder.Services.AddHttpClient<GeminiAnalyzerService>();
builder.Services.AddScoped<IResponseSimilarityService, ResponseSimilarityService>();

// ── Logging ───────────────────────────────────────────────────────────────
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var app = builder.Build();

app.UseHttpsRedirection();
app.MapControllers();


app.Run();
