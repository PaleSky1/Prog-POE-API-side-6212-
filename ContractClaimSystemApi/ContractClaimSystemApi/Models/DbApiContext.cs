using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ContractClaimSystemApi.Models
{
    public partial class DbApiContext : IdentityDbContext<IdentityUser, IdentityRole, string,
            IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>,
            IdentityRoleClaim<string>, IdentityUserToken<string>>
    {
        public DbApiContext()
        {
        }
        public DbApiContext(DbContextOptions<DbApiContext> options)
    :   base(options)
        {
        }

        public virtual DbSet<TblUser> TblUser { get; set; }

        public virtual DbSet<TblClaim> TblClaims { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                optionsBuilder.UseSqlServer("Server=DESKTOP-JA8J3O2;Initial Catalog=ClaimsDb;Integrated Security=True;Encrypt=False;");
            }
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // TblUser Configuration
            modelBuilder.Entity<TblUser>(entity =>
            {
                entity.HasKey(e => e.UserId).HasName("PK_tbluser");
                entity.ToTable("tblUsers");
                entity.Property(e => e.UserId).ValueGeneratedOnAdd();
                entity.Property(e => e.Username)
                    .HasMaxLength(255)
                    .IsUnicode(false);
                entity.Property(e => e.Password)
                    .HasMaxLength(255)
                    .IsUnicode(false);
                entity.Property(e => e.Email)
                    .HasMaxLength(255)
                    .IsUnicode(false);
                entity.Property(e => e.Role)
                    .HasMaxLength(50)
                    .IsUnicode(false);
            });
            // TblClaim Configuraration
            modelBuilder.Entity<TblClaim>(entity =>
            {
                entity.HasKey(e => e.ClaimId).HasName("PK_tblClaim");
                entity.ToTable("tblClaims");
                entity.Property(e => e.ClaimId).HasColumnName("ClaimID").ValueGeneratedOnAdd();
                entity.Property(e => e.HoursWorked).HasColumnType("decimal(18,2)");
                entity.Property(e => e.HourlyRate).HasColumnType("decimal(18,2)");
                entity.Property(e => e.TotalPayment).HasColumnType("decimal(18,2)");
                entity.Property(e => e.Status).HasMaxLength(50).IsUnicode(false);
                entity.HasOne(d => d.User).WithMany(p => p.TblClaims).HasForeignKey(d => d.UserId).OnDelete(DeleteBehavior.ClientSetNull).HasConstraintName("FK_tblClaim_tblUser");
            });

            // Identity relationships
            modelBuilder.Entity<IdentityUserLogin<string>>()
                .HasKey(login => new { login.LoginProvider, login.ProviderKey });
            modelBuilder.Entity<IdentityUserRole<string>>()
                .HasKey(role => new { role.UserId, role.RoleId });
            modelBuilder.Entity<IdentityUserToken<string>>()
                .HasKey(token => new { token.UserId, token.LoginProvider, token.Name });

            OnModelCreatingPartial(modelBuilder);
        }
        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
