using IdentityApi.Authorization;
using IdentityApi.Helpers;
using IdentityApi.Models;
using IdentityApi.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
{
	var services = builder.Services;
	var configuration = builder.Configuration;

	// configure strongly typed settings object
	services.Configure<IdentityServiceDatabaseSettings>(
		configuration.GetSection("IdentityServiceDatabase"));
	services.Configure<AppSettings>(
		configuration.GetSection("AppSettings"));

	services.AddCors(options =>
	{
		options.AddPolicy("AllowAll",
			builder =>
			{
				builder.AllowAnyOrigin()
					.AllowAnyMethod()
					.AllowAnyHeader();
			});
	});

	services.AddControllers();
	services.AddHealthChecks();

	// configure DI for application services
	services.AddScoped<IIdentitiesService, IdentitiesService>();
	services.AddScoped<IJwtUtils, JwtUtils>();
	services.AddScoped<IAuthService, AuthService>();
}

var app = builder.Build();

// Configure the HTTP request pipeline.

if (app.Environment.IsDevelopment())
{
	app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();

// global error handler
app.UseMiddleware<ErrorHandlerMiddleware>();

app.UseAuthentication();
app.UseRouting();

app.UseCors("AllowAll");

// custom jwt auth middleware
app.UseMiddleware<JwtMiddleware>();

app.UseEndpoints(endpoints =>
{
	endpoints.MapControllers();
	endpoints.MapHealthChecks("/health");
});

app.Run();
