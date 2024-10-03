package com.example.security_jwt.service;

import com.example.security_jwt.model.Product;
import com.example.security_jwt.repository.ProductRepository;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {

    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @PostAuthorize("hasRole('ADMIN')")
    public Product getProductById(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found with id: " + id));
    }

    @PreAuthorize("hasAnyRole('USER,ADMIN')")
    public List<Product> getProductsAll() {
        return productRepository.findAll();
    }
}
