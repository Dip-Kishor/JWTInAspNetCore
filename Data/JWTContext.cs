using JWTInAspNetCore.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTInAspNetCore.Data
{
    public class JWTContext(DbContextOptions<JWTContext> options) : IdentityDbContext<AppUser>(options)
    {
    }
}