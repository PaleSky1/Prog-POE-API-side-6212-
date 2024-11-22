namespace ContractClaimSystemApi.Models
{
    public class TblUser
    {
        public Guid UserId { get; set; } 
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string Role { get; set; } = null!; 
        public virtual ICollection<TblClaim> TblClaims { get; set; } = new List<TblClaim>();
    }
}
