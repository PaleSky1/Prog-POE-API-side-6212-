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

            // Configure Database Context
            builder.Services.AddDbContext<DbApiContext>(options =>
                options.UseSqlServer("Server=DESKTOP-JA8J3O2;Initial Catalog=ClaimsDb;Integrated Security=True;Encrypt=False;"));

            // Configure Identity
            builder.Services.AddIdentity<IdentityUser, IdentityRole>(options => { })
                .AddEntityFrameworkStores<DbApiContext>()
                .AddDefaultTokenProviders();

            // Add Authorization and Authentication
            builder.Services.AddAuthorization();
            builder.Services.AddEndpointsApiExplorer();

            // Add Swagger with Bearer Token support
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
                    Description = "Enter your valid token in the text input below.\n\nExample: \"Bearer abcdef12345\""
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

            // Ensure roles are created
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

            #region User Registration and Login Endpoints
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
            #endregion

            #region Claims Endpoints
            app.MapPost("/claims", async (TblClaim claim, DbApiContext dbContext) =>
            {
                if (claim == null)
                {
                    return Results.BadRequest("Claim data is null");
                }

                dbContext.TblClaim.Add(claim);
                await dbContext.SaveChangesAsync();
                return Results.Created($"/claims/{claim.ClaimId}", claim);
            }).WithName("CreateClaim").WithOpenApi();

            app.MapGet("/claims", async (DbApiContext dbContext) =>
            {
                var claims = await dbContext.TblClaim.ToListAsync();
                return Results.Ok(claims);
            }).WithName("GetClaims").WithOpenApi();

            app.MapGet("/claims/{id:guid}", async (Guid id, DbApiContext dbContext) =>
            {
                var claim = await dbContext.TblClaim.FindAsync(id);
                if (claim == null)
                {
                    return Results.NotFound($"Claim with ID {id} not found");
                }
                return Results.Ok(claim);
            }).WithName("GetClaimById").WithOpenApi();

            app.MapDelete("/claims/{id:guid}", async (Guid id, DbApiContext dbContext) =>
            {
                var claim = await dbContext.TblClaim.FindAsync(id);
                if (claim == null)
                {
                    return Results.NotFound($"Claim with ID {id} not found");
                }

                dbContext.TblClaim.Remove(claim);
                await dbContext.SaveChangesAsync();
                return Results.Ok($"Claim with ID {id} deleted");
            }).WithName("DeleteClaim").WithOpenApi();
            #endregion

            #region Users Endpoints
            app.MapDelete("/users/{username}", async (string username, DbApiContext dbContext) =>
            {
                var user = await dbContext.TblUser.FirstOrDefaultAsync(u => u.Username == username);
                if (user == null)
                {
                    return Results.NotFound($"User with username {username} not found");
                }

                dbContext.TblUser.Remove(user);
                await dbContext.SaveChangesAsync();
                return Results.Ok($"User with username {username} deleted");
            }).WithName("DeleteUser").WithOpenApi();
            #endregion

            app.Run();
        }

        #region Generate JWT Token with User Roles
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
