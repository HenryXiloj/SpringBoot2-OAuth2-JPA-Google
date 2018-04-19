package com.hxiloj.test.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/ws")
public class UserRestController {

    @RequestMapping(value = "user", method = RequestMethod.GET)
    public Principal user(Principal user) {
        return user;
    }
}
