using System;
using System.ComponentModel.DataAnnotations;

namespace SampleSecuredWeb.Models;

    public class User
    {
        [Key]
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string RoleName { get; set; } = null!;
    }
