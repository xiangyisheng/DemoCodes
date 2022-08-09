using Demo.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var services = builder.Services;
var Configuration = builder.Configuration;

// ASP.NET Core �е�����: https://docs.microsoft.com/zh-cn/aspnet/core/fundamentals/configuration/?view=aspnetcore-6.0
var jwtSection = Configuration.GetSection(JWTSettings.Position);
services.Configure<JWTSettings>(jwtSection);
var jwtOptions = jwtSection.Get<JWTSettings>();
//���jwt��֤
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,//�Ƿ���֤Issuer
            ValidateAudience = true,//�Ƿ���֤Audience
            ValidateLifetime = true,//�Ƿ���֤ʧЧʱ��
            ClockSkew = TimeSpan.FromSeconds(30),
            ValidateIssuerSigningKey = true,//�Ƿ���֤SecretKey
            ValidAudience = jwtOptions.Audience,//Audience
            ValidIssuer = jwtOptions.Issuer,//Issuer���������ǰ��ǩ��jwt������һ��
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SecretKey))//�õ�SecretKey
        };
    });

services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
services.AddEndpointsApiExplorer();

#region Http Scheme
services.AddSwaggerGen(swagger =>
{
    swagger.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "JWT Token Authentication API",
        Description = "ASP.NET Core 6.0 Web API"
    });
    var securityDefinition = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Specify the authorization token.",
    };
    swagger.AddSecurityDefinition("JwtAuth", securityDefinition);
    var securityScheme = new OpenApiSecurityScheme()
    {
        Reference = new OpenApiReference()
        {
            Id = "JwtAuth",
            Type = ReferenceType.SecurityScheme
        }
    };
    var securityRequirements = new OpenApiSecurityRequirement()
    {
        {securityScheme, new string[] { }},
    };
    swagger.AddSecurityRequirement(securityRequirements);
});
#endregion
#region ApiKey Scheme
//services.AddSwaggerGen(swagger =>
//{
//    //This is to generate the Default UI of Swagger Documentation  
//    swagger.SwaggerDoc("v1", new OpenApiInfo
//    {
//        Version = "v1",
//        Title = "JWT Token Authentication API",
//        Description = "ASP.NET Core 6.0 Web API"
//    });
//    // To Enable authorization using Swagger (JWT)  
//    swagger.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
//    {
//        Name = "Authorization",
//        Type = SecuritySchemeType.ApiKey,
//        Scheme = "Bearer",
//        BearerFormat = "JWT",
//        In = ParameterLocation.Header,
//        Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 12345abcdef\"",
//    });
//    swagger.AddSecurityRequirement(new OpenApiSecurityRequirement
//    {
//        {
//            new OpenApiSecurityScheme
//            {
//                Reference = new OpenApiReference
//                {
//                    Type = ReferenceType.SecurityScheme,
//                    Id = "Bearer"
//                }
//            },
//            new string[] {}
//        }
//    });
//}); 
#endregion

var app = builder.Build();
var env = app.Environment;

// Configure the HTTP request pipeline.
if (env.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

///���jwt��֤
app.UseAuthorization();

app.MapControllers();

app.Run();
