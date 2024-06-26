package com.monetique.springjwt.repository;


import com.monetique.springjwt.models.Cardholder;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CardholderRepository extends JpaRepository<Cardholder, Long> {
    Optional<Cardholder> findByCardNumberAndCinAndPhoneNumber( String cardNumber, String cin, String phoneNumber);
    Optional<Cardholder> findPinByPhoneNumber(String phoneNumber);

}