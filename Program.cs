using System.Text;
using JWTInAspNetCore.Data;
using JWTInAspNetCore.Middleware;
using JWTInAspNetCore.Models;
using JWTInAspNetCore.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;

var builder = WebApplication.CreateBuilder(args);
//database connection
builder.Services.AddDbContext<JWTContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("JWTContext")));

//adding identity
builder.Services.AddIdentity<AppUser, IdentityRole>()
.AddEntityFrameworkStores<JWTContext>()
.AddSignInManager()
.AddRoles<IdentityRole>();


builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddHttpContextAccessor();
// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();


builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,
        ValidIssuer = builder.Configuration["AccessToken:Issuer"],
        ValidAudience = builder.Configuration["AccessToken:Audience"],
        ClockSkew = TimeSpan.Zero,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["AccessToken:Key"]!))
    };
});


builder.Services.AddSwaggerGen(Options=>{
    Options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme{
        In=ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    Options.OperationFilter<SecurityRequirementsOperationFilter>();
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseMiddleware<TokenRenewalMiddleWare>();
app.UseAuthorization();

app.MapControllers();

app.Run();
