package com.sso.login.controller;


import com.alibaba.fastjson.JSONObject;
import com.sso.common.util.RedisUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.print.DocFlavor;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

/**
 * Created by zhaokai on 2017/10/18.
 */
@Controller
@RequestMapping("/sso")
public class SsoController {

    @RequestMapping("/index")
    public String index(HttpServletRequest request,HttpServletResponse response){
        Subject subject = SecurityUtils.getSubject();
        String username = (String)subject.getPrincipal();
        if (!"".equals(username) && null!=username){
            request.setAttribute("username",username);
        }else{
            request.setAttribute("username","null");
        }
        return "/index.jsp";
    }

    /**
     * 认证code
     * @param request
     * @param response
     * @return
     */
    @RequestMapping("/code")
    @ResponseBody
    public String code(HttpServletRequest request, HttpServletResponse response){
        JSONObject object = new JSONObject();
        String codeParam = request.getParameter("code");
        String code = RedisUtil.get("sso_server_code" + "_" + codeParam);
        if (StringUtils.isBlank(codeParam) || !codeParam.equals(code)) {
            object.put("code",-1);
            object.put("result","无效code");
            return object.toString();
        }
        object.put("code",1);
        object.put("result",code);
        return object.toString();
    }

    @RequestMapping("/loginsucc")
    public String loginsucc(){
        return "/loginsucc.jsp";
    }

    /**
     * 登录
     * @param response
     * @param request
     * @return
     */
    @RequestMapping(value = "/login",method = RequestMethod.POST)
    public String login(HttpServletResponse response,HttpServletRequest request,ModelMap modelMap){
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        String serverSessionId = RedisUtil.get("sso_server_session_"+session.getId().toString());
        if (StringUtils.isEmpty(serverSessionId)){
            UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username,password);
            try {
                subject.login(usernamePasswordToken);
            }catch (Exception e){
                return "登录失败";
            }
            String code = UUID.randomUUID().toString();
            RedisUtil.lpush("sso_server_session_ids",session.getId().toString());
            RedisUtil.set("sso_server_session_id_"+session.getId().toString(),code);
            RedisUtil.set("sso_server_code_"+code,code);
        }
        // 回跳登录前地址
        String backurl = request.getParameter("backurl");
        if (StringUtils.isBlank(backurl)) {
            return "redirect:/sso/loginsucc";
        } else {
            return "redirect:"+backurl;
        }
    }

    /**
     * 接口登录
     * @param request
     * @return
     */
    @RequestMapping(value = "/login",method = RequestMethod.GET)
    public String login(HttpServletRequest request){
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        String code = RedisUtil.get("sso_server_session_id_"+session.getId().toString());
        if (StringUtils.isNotEmpty(code)){
            String backurl = request.getParameter("backurl");
            String username = (String)subject.getPrincipal();
            if (StringUtils.isBlank(backurl)) {
                backurl = "/";
            } else {
                if (backurl.contains("?")) {
                    backurl += "&code=" + code + "&username=" + username;
                } else {
                    backurl += "?code=" + code + "&username=" + username;
                }
            }
            return "redirect:"+backurl;
        }else{
            return "/index.jsp";
        }
    }
}
