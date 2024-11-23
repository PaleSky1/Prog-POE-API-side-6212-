namespace ContractClaimSystemApi.Models
{
    public partial class TblClaim
    {
        public Guid ClaimId { get; set; }
        public Guid UserId { get; set; } 
        public double HoursWorked { get; set; }
        public double HourlyRate { get; set; }
        public double TotalPayment { get; set; }
        public string Status { get; set; } 
        public virtual TblUser User { get; set; } = null!; 
    }
}
