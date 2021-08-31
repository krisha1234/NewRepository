using AutoMapper;
using LoginDemo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace LoginDemo.Controllers
{
    public class AccountController:Controller
    {
        private UserManager<IdentityUser> _userManager;
        private SignInManager<IdentityUser> _signInManager;
        private IMapper _mapper;
        private readonly ILogger _logger;
        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IMapper mapper, ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _mapper = mapper;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel register)
        {
            if (ModelState.IsValid)
            {
                var User = new IdentityUser
                {
                    UserName = register.Email,
                    Email = register.Email,
                };

                var result = await _userManager.CreateAsync(User, register.Password);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(User, isPersistent: false);
                    return RedirectToAction("index", "Home");
                }
                foreach(var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                ModelState.AddModelError(string.Empty, "invalid login attempt");
            }
            return View(register);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnURL = null)
        {
            ViewData["ReturnURl"] = returnURL;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            //if (ModelState.IsValid)
            //{
            //    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password,model.RememberMe,false);
            //    if (result.Succeeded)
            //    {
            //        return RedirectToAction("index", "Home");

            //    }
            //    ModelState.AddModelError(string.Empty, "Invalid Login Attempt");
            //}
            //return View(model);

            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if(user!=null 
                && await _userManager.CheckPasswordAsync(user, model.Password))
            {

                var identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
                identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
                await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme,
                    new ClaimsPrincipal(identity));
                return RedirectToLocal(returnUrl);
            }
            else
            {
                ModelState.AddModelError("", "Invalid UserName or Password");
                return View();
            }

        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login");
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);
            else
                return RedirectToAction(nameof(HomeController.Index), "Home");

        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if(user!=null && await _userManager.IsEmailConfirmedAsync(user))
                {
                    var passwordtoken = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var passwordResetLink = Url.Action("ForgotPassword", "Account", new { email = model.Email, token = passwordtoken }, Request.Scheme);
                    
                   
                    _logger.Log(LogLevel.Warning, passwordResetLink);
                    return View("ForgotPasswordConfirmation");
                }
                return View("ForgotPasswordConfirmation");

            }
            return View(model);
        }
    }
}
