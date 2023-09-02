package com.devcourse.be04daangnmarket.image.domain;

import com.devcourse.be04daangnmarket.common.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "images")
public class File extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String type;

    @Column(nullable = false)
    private long size;

    @Column(nullable = false)
    private String path;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private DomainName domainName;

    @Column(nullable = false)
    private Long domainId;

    protected File() {
    }

    public File(String name, String type, long size, String path, DomainName domainName, Long domainId) {
        this.name = name;
        this.type = type;
        this.size = size;
        this.path = path;
        this.domainName = domainName;
        this.domainId = domainId;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public String getPath() {
        return path;
    }

    public long getSize() {
        return size;
    }

    public DomainName getDomainName() {
        return domainName;
    }

    public Long getDomainId() {
        return domainId;
    }
}