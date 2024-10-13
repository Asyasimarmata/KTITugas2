using System;
using Microsoft.AspNetCore.Mvc;
using SampleSecuredWeb.Data;
using SampleSecuredWeb.Models;


namespace SampleSecuredWeb.Controllers
{
    public class StudentController : Controller
    {
        private readonly IStudent _studentsData;

        public StudentController(IStudent studentData)
        {
            _studentsData = studentData;
        }
        public IActionResult Index()
        {
            var students = _studentsData.GetStudents();
            return View(students);
        }
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Create(Student student)
        {
           try
           {
             _studentsData.AddStudent(student);
                return RedirectToAction("Index");
           }
           catch (System.Exception ex)
           {
            
            ViewBag.Error = ex.Message;
           }
            
            return View(student);
            
        }

        public IActionResult Edit(){
            return View();
        }
        public IActionResult Delete(){
            return View();
        }
    }
}