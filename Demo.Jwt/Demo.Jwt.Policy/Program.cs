using Demo.Jwt.Policy;
using Demo.Jwt.Policy.AuthManagement;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var services = builder.Services;
var Configuration = builder.Configuration;
var env = builder.Environment;

services.AddSingleton(new Appsettings(env.ContentRootPath));
services.AddMemoryCache();

string securityKey = Appsettings.app(new string[] { "JwtSettings", "SecurityKey" });
string issuer = Appsettings.app(new string[] { "JwtSettings", "Issuer" });
string audience = Appsettings.app(new string[] { "JwtSettings", "Audience" });
//��Ӳ��Լ�Ȩģʽ
services.AddAuthorization(options =>
{
    options.AddPolicy("Permission", policy => policy.Requirements.Add(new PolicyRequirement()));
})
.AddAuthentication(s =>
{
    //���JWT Scheme
    s.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    s.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    s.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
//���jwt��֤��
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateLifetime = true,//�Ƿ���֤ʧЧʱ��
        ClockSkew = TimeSpan.FromSeconds(30),

        ValidateAudience = true,//�Ƿ���֤Audience
        ValidAudience = audience,//Audience
        ValidateIssuer = true,//�Ƿ���֤Issuer
        ValidIssuer = issuer,//Issuer���������ǰ��ǩ��jwt������һ��

        ValidateIssuerSigningKey = true,//�Ƿ���֤SecurityKey
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey))//�õ�SecurityKey
    };
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            //Token expired
            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
            {
                context.Response.Headers.Add("Token-Expired", "true");
            }
            return Task.CompletedTask;
        }
    };
});

//ע����ȨHandler
services.AddSingleton<IAuthorizationHandler, PolicyHandler>();

services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
services.AddEndpointsApiExplorer();

services.AddSwaggerGen(swagger =>
{
    //This is to generate the Default UI of Swagger Documentation  
    swagger.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "JWT Token Authentication API",
        Description = "ASP.NET Core 6.0 Web API"
    });
    // To Enable authorization using Swagger (JWT)  
    swagger.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 12345abcdef\"",
    });
    swagger.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
