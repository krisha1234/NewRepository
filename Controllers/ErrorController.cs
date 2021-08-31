using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace LoginDemo.Controllers
{
    [ApiController]
    public class ErrorController : Controller
    {
        [Route("/error")]
        public IActionResult Error()
        {
           var exception =  HttpContext.Features.Get<IExceptionHandlerPathFeature>();
            var statusCode = exception.Error.GetType().Name switch
            {
                "ArgumentException" => HttpStatusCode.BadRequest,
                _ => HttpStatusCode.ServiceUnavailable
            };

            ViewBag.Path = exception.Path;
            ViewBag.Message = exception.Error.Message;
            ViewBag.Stacktrace = exception.Error.StackTrace;

            //return Problem(detail: exception.Error.Message, statusCode:(int) statusCode);
            return View("ErrorView");
        }
        
    }
}
