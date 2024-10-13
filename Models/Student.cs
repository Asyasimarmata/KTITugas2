using System;
using System.ComponentModel.DataAnnotations;

namespace SampleSecuredWeb.Models;
public class Student
{
    [Key]
    public string Nim { get; set; } = null!;
    public string FullName { get; set; } = null!;
}
