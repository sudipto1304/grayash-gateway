package com.grayash.gateway.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Data;

@Entity
@Table(name = "user_information")
@Data
public class UserEntity implements Serializable {

    @Id
    @Column(name="CUSTOMER_ID")
    private String customerId;

    @Column(name="PASSWORD")
    private String password;

    @Column(name="FIRST_NAME")
    private String firstName;

    @Column(name="LAST_NAME")
    private String lastName;

    @Column(name="ZIP_CODE")
    private Long zipCode;

    @Column(name="ADDRESS")
    private String address;

    @Column(name="UPDATE_TIME")
    private String lastUpdateTime;

    @Column(name="COUNTRY_CODE")
    private String countryCode;

    @Column(name="SOCIAL_MEDIA_TYPE")
    private String socialMedia;

    @Column(name="ACCOUNT_STATUS")
    private String accountStatus;

    @Column(name="PHONE_VERIFIED")
    private String phoneVerify;


    @Column(name="USER_ID")
    private String userId;

    @Column(name="EMAIL_ID")
    private String emailId;

    @Column(name="PHONE_NUMBER")
    private String phoneNumber;


}