using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SampleSecuredWeb.Data;
using SampleSecuredWeb.Models;
using SampleSecuredWeb.ViewModel;
using System.Text.RegularExpressions; 
using System.Security.Cryptography; 
using BCrypt.Net;


namespace SampleSecuredWeb.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUser _userData;
        public AccountController(IUser user)
        {
            _userData = user;
        }

        // GET: AccountController
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(RegistrationViewModel registrationViewModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    // Validasi password kuat (minimal 12 karakter, huruf besar, kecil, dan angka)
                    if (!IsValidPassword(registrationViewModel.Password))
                    {
                        ViewBag.Error = "Password harus mengandung 12 karakter,huruf besar&kecil, dan angka.";
                        return View(registrationViewModel);
                    }

                    // Hash password
                    var hashedPassword = HashPassword(registrationViewModel.Password);
                    var user = new Models.User
                    {
                        Username = registrationViewModel.Username,
                        Password = hashedPassword,
                        RoleName = "contributor"
                    };
                    _userData.Registration(user);
                    return RedirectToAction("Index", "Home");
                }
            }
            catch (System.Exception ex)
            {
                ViewBag.Error = ex.Message;

            }
            return View(registrationViewModel);
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel)
        {
            try
            {
                loginViewModel.ReturnUrl = loginViewModel.ReturnUrl ?? Url.Content("~/");

                var user = new User
                {
                    Username = loginViewModel.Username,
                    Password = loginViewModel.Password
                };

                var loginUser = _userData.Login(user);
                if (loginUser == null)
                {
                    ViewBag.Message = "Invalid login attempt.";
                    return View(loginViewModel);
                }

                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Username)
                    };
                var identity = new ClaimsIdentity(claims,
                    CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = loginViewModel.RememberLogin
                    });
                return RedirectToAction("Index", "Home");


            }
            catch (System.Exception ex)
            {
                ViewBag.Message = ex.Message;
            }
            return View(loginViewModel);
        }
        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(bytes);
            }
        }

        public class PasswordService
    {
        // Menggunakan BCrypt untuk hashing password
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public bool VerifyPassword(string enteredPassword, string storedHashedPassword)
        {
            // Menggunakan BCrypt untuk memverifikasi password
            return BCrypt.Net.BCrypt.Verify(enteredPassword, storedHashedPassword);
        }
    }


        // Validasi password kuat
        private bool IsValidPassword(string password)
        {
            return password.Length >= 12 &&
                   Regex.IsMatch(password, @"[a-z]") &&  // Huruf kecil
                   Regex.IsMatch(password, @"[A-Z]") &&  // Huruf besar
                   Regex.IsMatch(password, @"[0-9]");    // Angka
        }

    }
}