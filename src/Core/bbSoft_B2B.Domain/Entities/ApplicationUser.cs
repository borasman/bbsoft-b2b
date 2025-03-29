using Microsoft.AspNetCore.Identity;
using System;

namespace bbSoft_B2B.Domain.Entities;

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedOn { get; set; } = DateTime.UtcNow;
    public DateTime? LastModifiedOn { get; set; }
    
    // Two-Factor Authentication özelliği Identity'de zaten var (TwoFactorEnabled property)
    
    // Tam isim için hesaplanmış property
    public string FullName => $"{FirstName} {LastName}".Trim();
}