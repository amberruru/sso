package com.sso.login.controller;


import com.alibaba.fastjson.JSONObject;
import com.sso.common.util.RedisUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

/**
 * Created by zhaokai on 2017/10/18.
 */
@Controller
@RequestMapping("/sso")
public class SsoController {

    /**
     * 认证code
     * @param request
     * @param response
     * @return
     */
    @RequestMapping("/code")
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

    /**
     * 登录
     * @param response
     * @param request
     * @return
     */
    @RequestMapping("/login")
    public String login(HttpServletResponse response,HttpServletRequest request){
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
            return "redirect:/";
        } else {
            return "redirect:"+backurl;
        }
    }

    /**
     * 接口登录
     * @param request
     * @return
     */
    @RequestMapping("/login")
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
                    backurl += "&upms_code=" + code + "&upms_username=" + username;
                } else {
                    backurl += "?upms_code=" + code + "&upms_username=" + username;
                }
            }
            return "redirect:"+backurl;
        }else{
            return "sso/login.jsp";
        }
    }
}
