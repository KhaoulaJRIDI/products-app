package com.app.backend.repositories;

import com.app.backend.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;

import java.awt.print.Pageable;

@RepositoryRestResource
public interface ProductRepository extends JpaRepository<Product,String>
{

   // public Page<Product> findByDesignationContains(String mc, Pageable pageable);
}
