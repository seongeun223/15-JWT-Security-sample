package com.ohgiraffers.jwt.test.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test")
public class TestController {

    // USER일 때 사용가능함
    @PreAuthorize("hasAuthority('USER')")
    // 컨트롤러 메소드에 매번 붙여야 함
    @GetMapping("/user")
    public String testUser() {
        return "user 권한만 접근 가능한 test success";
    }

    // ADMIN일 때 사용가능함
    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/admin")
    public String testAdmin() {
        return "Admin 권한만 접근 가능한 test success";
    }
}
