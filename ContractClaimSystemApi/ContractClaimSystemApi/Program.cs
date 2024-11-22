using ContractClaimSystemApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ContractClaimSystemApi
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddDbContext<DbApiContext>(options =>
                options.UseSqlServer("Server=DESKTOP-JA8J3O2;Initial Catalog=ClaimsDb;Integrated Security=True;Encrypt=False;"));

            builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
            {
            })
            .AddEntityFrameworkStores<DbApiContext>()
            .AddDefaultTokenProviders();


            builder.Services.AddAuthorization();
            builder.Services.AddEndpointsApiExplorer();


            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo { Title = "Contract Claim System API", Version = "v1" });


                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "Enter your valid token in the text input below.\n\nExample: \" abcdef12345\""
                });

                options.AddSecurityRequirement(new OpenApiSecurityRequirement
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

            using (var scope = app.Services.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                await EnsureRolesAsync(roleManager);
            }

            app.UseSwagger();
            app.UseSwaggerUI();

            app.UseHttpsRedirection();
            app.UseAuthentication();
            app.UseAuthorization();

            #region User Registration and Login
            app.MapPost("/register", async (UserRegistrationDto model, UserManager<IdentityUser> userManager,
                RoleManager<IdentityRole> roleManager, DbApiContext dbContext) =>
            {
                var user = new IdentityUser { UserName = model.Username, Email = model.Email };
                var result = await userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, model.Role);
                    var tblUser = new TblUser
                    {
                        UserId = Guid.Parse(user.Id),
                        Username = model.Username,
                        Password = model.Password,
                        Email = model.Email,
                        Role = model.Role
                    };
                    dbContext.TblUser.Add(tblUser);
                    await dbContext.SaveChangesAsync();
                    return Results.Created($"/users/{user.UserName}", user);
                }
                return Results.BadRequest(result.Errors);
            }).WithName("RegisterUser").WithOpenApi();

            app.MapPost("/login", async (UserLoginDto model, SignInManager<IdentityUser> signInManager,
                UserManager<IdentityUser> userManager) =>
            {
                var user = await userManager.FindByNameAsync(model.Username);
                if (user != null)
                {
                    var result = await signInManager.PasswordSignInAsync(model.Username, model.Password, false, false);
                    if (result.Succeeded)
                    {
                        var token = GenerateJwtToken(user, userManager);
                        return Results.Ok(new { Token = token });
                    }
                }
                return Results.Unauthorized();
            }).WithName("LoginUser").WithOpenApi();

            app.MapGet("/admin", [Authorize(Roles = "Admin")] () => "Welcome Admin").WithName("AdminEndpoint").WithOpenApi();
            app.MapGet("/user", [Authorize(Roles = "User")] () => "Welcome User").WithName("UserEndpoint").WithOpenApi();
            #endregion

            app.Run();
        }

        #region Generate JWT Token with User Rights
        private static string GenerateJwtToken(IdentityUser user, UserManager<IdentityUser> userManager)
        {
            var userRoles = userManager.GetRolesAsync(user).Result;
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("JqOUYUlWx8kNhO+3C6vAZkBGH19Vk6rfoWabDw3hDZY="));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "ContractClaimSystemApi",
                audience: "ContractClaimSystemApi",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        #endregion

        #region Add User Roles to DB
        private static async Task EnsureRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            var roles = new[] { "Admin", "User" };

            foreach (var role in roles)
            {
                var roleExist = await roleManager.RoleExistsAsync(role);
                if (!roleExist)
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }
        }
        #endregion
    }
}



