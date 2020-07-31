using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Angular10.Areas.Admin.Controllers
{
    
    [Area("Admin")]
    [Authorize(AuthenticationSchemes = "Admin")]
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
