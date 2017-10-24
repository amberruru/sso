package com.sso.module1.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by zhaokai on 2017/10/23.
 */
@Controller
@RequestMapping("/manage")
public class module1Controller {

    @RequestMapping("/getsession")
    public String getsession(HttpServletRequest request , HttpServletResponse response){
        Subject subject = SecurityUtils.getSubject();
        String username = (String)subject.getPrincipal();
        request.setAttribute("username",username);
        return "/get_session.jsp";
    }
}
